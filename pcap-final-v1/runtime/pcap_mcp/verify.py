"""Re-extract HTTP evidence from an authorized capture without asking an LLM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .claims import check_claims, parse_claims
from .provenance import (
    HTTP_FIELDS,
    LOCATORS,
    MAX_FIELD_RECORDS,
    MAX_HTTP_ROWS,
    build_records,
    capture_digest,
    parse_tool_payload,
)
from .tshark import PcapError, http_field_rows, resolve_capture


def verify_evidence(
    capture: Path,
    evidence: list[dict[str, Any]],
    claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = resolve_capture(str(capture))
    before = capture_digest(path)
    results: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for item in evidence:
        payload = parse_tool_payload(item.get("result", ""))
        if not payload or payload.get("schema") != "pcap-mcp.http-fields/v1":
            continue
        records = payload.get("field_records", [])
        if not isinstance(records, list) or len(records) > MAX_FIELD_RECORDS:
            raise ValueError("Invalid field record list.")
        refs = [f"{item['id']}/{r['record_id']}" for r in records]
        error = None
        if len(set(refs)) != len(refs) or seen_refs.intersection(refs):
            error = "duplicate_reference"
        elif payload.get("capture_sha256") != before:
            error = "capture_hash_mismatch"
        elif item.get("error") or item.get("truncated") or payload.get("truncated"):
            error = "incomplete_tool_evidence"
        seen_refs.update(refs)
        frames = sorted({r["frame_number"] for r in records})
        if any(type(n) is not int or not 1 <= n <= 2**32 - 1 for n in frames):
            raise ValueError("Invalid frame locator.")
        if len(frames) > MAX_HTTP_ROWS:
            raise ValueError("Too many frame locators.")
        regenerated: dict[str, dict[str, Any]] = {}
        if not error and frames:
            rows = []
            # The public filter boundary permits at most 512 characters. Batch at
            # most ten uint32 frame IDs, instead of weakening that boundary.
            for offset in range(0, len(frames), 10):
                group = frames[offset : offset + 10]
                expression = (
                    "http.request && (" + " || ".join(f"frame.number == {n}" for n in group) + ")"
                )
                selected, truncated = http_field_rows(
                    path, [*LOCATORS, *HTTP_FIELDS], expression, MAX_HTTP_ROWS
                )
                rows.extend(selected)
                if truncated:
                    error = "verification_output_truncated"
            policies = {r["transformations"]["redaction_enabled"] for r in records}
            if len(policies) != 1 or any(type(p) is not bool for p in policies):
                raise ValueError("Invalid redaction policy in evidence.")
            rebuilt, limited = build_records(rows, redact_enabled=policies.pop())
            if limited:
                error = "verification_record_limit"
            regenerated = {r["record_id"]: r for r in rebuilt}
        for ref, record in zip(refs, records, strict=True):
            actual = regenerated.get(record["record_id"])
            matched = not error and json.dumps(actual, sort_keys=True) == json.dumps(
                record, sort_keys=True
            )
            results.append(
                {
                    "reference": ref,
                    "matched": bool(matched),
                    "status": error or ("matched" if matched else "field_record_mismatch"),
                }
            )
    after = capture_digest(path)
    if before != after:
        for result in results:
            result.update(matched=False, status="capture_changed_during_verification")
    verified = {r["reference"] for r in results if r["matched"]}
    output: dict[str, Any] = {
        "schema_version": 1,
        "capture_sha256": before,
        "capture_unchanged_during_verification": before == after,
        "scope": "decoded_http_fields_and_transformations_not_intent_or_success",
        "records": results,
        "record_count": len(results),
        "matched_count": len(verified),
        "all_records_match": bool(results) and all(r["matched"] for r in results),
        "coverage": "only_exported_field_occurrences_not_entire_capture",
    }
    if claims is not None:
        output["claims"] = check_claims(claims, evidence, verified)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-read exported HTTP fields without an LLM")
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--evidence-json", required=True, type=Path)
    parser.add_argument("--claims-json", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence_json.read_text(encoding="utf-8"))
        if not isinstance(evidence, list):
            raise ValueError("Evidence must be a list.")
        claims = (
            parse_claims(args.claims_json.read_text(encoding="utf-8")) if args.claims_json else None
        )
        result = verify_evidence(args.capture, evidence, claims)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except (PcapError, ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"pcap-mcp-verify: {exc}\n")
    print(f"Matched {result['matched_count']}/{result['record_count']} records; see {args.output}")
    if not result["all_records_match"] or (
        claims is not None and not result["claims"]["all_facts_accepted"]
    ):
        parser.exit(1)


if __name__ == "__main__":
    main()
