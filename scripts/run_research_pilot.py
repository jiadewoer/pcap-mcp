"""Interleave three conditions by case, preserving all successes and failures."""

from __future__ import annotations

import argparse
import os
import random
from pathlib import Path

from pcap_mcp import __version__
from pcap_mcp.baseline import load_manifest, run
from pcap_mcp.research import write_json_atomic

CONDITIONS = {
    "flat-narrative": {"evidence_view": "flat", "report_format": "narrative"},
    "structured-narrative": {"evidence_view": "structured", "report_format": "narrative"},
    "structured-claims": {"evidence_view": "structured", "report_format": "claims"},
}


def schedule(case_ids: list[str], repeats: int, order_seed: int) -> list[dict]:
    rng = random.Random(order_seed)
    result = []
    for repeat in range(1, repeats + 1):
        cases = list(case_ids)
        rng.shuffle(cases)
        for case_id in cases:
            conditions = list(CONDITIONS)
            rng.shuffle(conditions)
            result.extend(
                {"case_id": case_id, "repeat": repeat, "condition": condition}
                for condition in conditions
            )
    return result


def source_comparisons(records: list[dict]) -> list[dict]:
    grouped = {}
    for record in records:
        key = (record["case_id"], record["repeat"])
        grouped.setdefault(key, {})[record["condition"]] = [
            item["canonical_payload_sha256"]
            for item in record["trial"].get("evidence_views", [])
        ]
    result = []
    for (case_id, repeat), conditions in grouped.items():
        complete = set(conditions) == set(CONDITIONS) and all(conditions.values())
        result.append({
            "case_id": case_id, "repeat": repeat,
            "complete": complete,
            "canonical_source_payloads_equal": (
                len({tuple(values) for values in conditions.values()}) == 1 if complete else None
            ),
        })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/field_cases.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--order-seed", type=int, default=2026)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--claims-response-format", choices=("json", "prompt"), default="json")
    args = parser.parse_args()
    if (
        not 1 <= args.repeats <= 100
        or not 2 <= args.max_rounds <= 12
        or not 0 <= args.seed <= 2**31 - 1
    ):
        parser.error("Invalid repeat, model seed or round budget.")
    if __version__ not in {"0.7.0", "0.8.0"}:
        parser.error("This pilot requires the 0.7.0 or 0.8.0 controller.")
    if not all(
        os.getenv(key, "").strip()
        for key in (
            "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL", "PCAP_MCP_ALLOWED_DIRS"
        )
    ):
        parser.error("Set model credentials/endpoint/model and allowed capture directories first.")
    manifest = args.manifest.resolve()
    cases = load_manifest(manifest)
    for case in cases:
        case["capture"] = str((manifest.parent / case["capture"]).resolve())
        if not Path(case["capture"]).is_file():
            parser.error("A manifest capture is missing.")
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    manifest_dir = root / "manifests"
    manifest_dir.mkdir()
    lookup = {}
    for case in cases:
        local = dict(case)
        local["capture"] = os.path.relpath(case["capture"], manifest_dir)
        path = manifest_dir / f"{case['id']}.json"
        write_json_atomic(path, {"schema_version": 1, "cases": [local]})
        lookup[case["id"]] = path
    planned = schedule(list(lookup), args.repeats, args.order_seed)
    protocol = {
        "schema_version": 1, "project_version": __version__,
        "conditions": CONDITIONS, "order_seed": args.order_seed,
        "temperature": 0.0, "model_seed": args.seed, "max_calls": 1,
        "max_rounds": args.max_rounds, "max_format_retries": 1,
        "claims_response_format": args.claims_response_format,
        "comparison_scope": "field_representation_and_restricted_reporting_protocol",
        "schedule": planned,
    }
    write_json_atomic(root / "protocol.json", protocol)
    records = []
    for index, item in enumerate(planned, 1):
        folder = root / item["condition"] / f"run-{index:03d}"
        print(
            f"[{index}/{len(planned)}] {item['condition']} / {item['case_id']}"
            f" / repeat {item['repeat']}", flush=True,
        )
        outcome = run(
            lookup[item["case_id"]], folder, repeats=1, max_calls=1,
            max_rounds=args.max_rounds, evidence_mode="field", temperature=0.0,
            seed=args.seed, claims_response_format=args.claims_response_format,
            evidence_view=CONDITIONS[item["condition"]]["evidence_view"],
            report_format=CONDITIONS[item["condition"]]["report_format"],
        )
        records.append(
            {
                **item,
                "trial": outcome["trials"][0],
                "artifact_directory": str(folder.relative_to(root)),
            }
        )
        write_json_atomic(root / "summary.json", {
            "protocol": protocol, "attempted_so_far": len(records), "planned": len(planned),
            "runs": records,
            "source_comparisons": source_comparisons(records),
            "completed": sum(record["trial"]["status"] == "completed" for record in records),
        })
    print(f"Saved all {len(records)} runs to {root}")


if __name__ == "__main__":
    main()
