"""Repeatable, deliberately narrow baseline for the PCAP investigation agent.

This runner measures observable tool use and citation syntax. It does not grade
whether a natural-language claim is supported by a packet; that needs review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .research import canonical_digest

SETTING_NAMES = (
    "PCAP_MCP_REDACT",
    "PCAP_MCP_MAX_FILE_MB",
    "PCAP_MCP_MAX_ROWS",
    "PCAP_MCP_TIMEOUT_S",
    "PCAP_MCP_MAX_OUTPUT_MB",
    "PCAP_MCP_MAX_RESULT_CHARS",
)


def load_manifest(path: Path) -> list[dict[str, Any]]:
    """Validate a small explicit test set, preserving its declared order."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Manifest must have schema_version: 1.")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Manifest must contain at least one case.")
    identifiers: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each case must be an object.")
        identifier = case.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,63}", identifier
        ):
            raise ValueError("Case IDs must be unique lowercase filename-safe strings.")
        if identifier in identifiers:
            raise ValueError(f"Duplicate case ID: {identifier}")
        identifiers.add(identifier)
        if not isinstance(case.get("capture"), str) or not case["capture"].strip():
            raise ValueError(f"{identifier}: capture is required.")
        if not isinstance(case.get("goal"), str) or not case["goal"].strip():
            raise ValueError(f"{identifier}: goal is required.")
        for key in ("required_tools", "warning_tools", "forbidden_warning_tools"):
            value = case.get(key, [])
            if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
                raise ValueError(f"{identifier}: {key} must be a list of tool names.")
    return cases


def score(report: str, evidence: list[dict[str, Any]], case: dict[str, Any]) -> dict[str, bool]:
    """Evaluate only mechanically observable properties, not semantic truth."""
    ids = [item.get("id") for item in evidence]
    observed = {item.get("tool") for item in evidence if not item.get("error")}
    warned = {item.get("tool") for item in evidence if item.get("security_warning")}
    # The automatically generated evidence index contains all IDs. Count only
    # citations in the report body, or a model could omit every citation and pass.
    body = report.split("\n## 证据索引\n", 1)[0]
    cited = set(re.findall(r"\[(E\d+)\]", body))
    checks = {
        "required_tools_called": set(case.get("required_tools", [])) <= observed,
        "expected_warnings_present": set(case.get("warning_tools", [])) <= warned,
        "citations_exist": bool(cited) and cited <= set(ids),
        "no_tool_errors": not any(item.get("error") for item in evidence),
        "no_truncated_results": not any(item.get("truncated") for item in evidence),
    }

    if "forbidden_warning_tools" in case:
        checks["unexpected_warnings_absent"] = not (set(case["forbidden_warning_tools"]) & warned)
    return checks


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    manifest: Path,
    output_dir: Path,
    *,
    repeats: int = 3,
    max_calls: int = 2,
    max_rounds: int = 3,
    request_timeout: int = 120,
    report_language: str = "zh",
    evidence_mode: str = "legacy",
    report_format: str = "narrative",
    evidence_view: str = "structured",
    max_format_retries: int = 1,
    claims_response_format: str = "json",
    temperature: float = 0.0,
    seed: int = 0,
) -> dict[str, Any]:
    """Run each case repeatedly with the same settings and retain every outcome."""
    if not 1 <= repeats <= 100:
        raise ValueError("Repeats must be between 1 and 100.")
    if not 1 <= max_calls <= 12 or not 2 <= max_rounds <= 12:
        raise ValueError("Invalid Agent call or round budget.")
    if not 15 <= request_timeout <= 600 or report_language not in {"auto", "zh", "en"}:
        raise ValueError("Invalid model timeout or report language.")
    if not all(
        os.getenv(key, "").strip() for key in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL")
    ):
        raise ValueError("Set OPENAI_API_KEY, OPENAI_BASE_URL and OPENAI_MODEL first.")
    if not os.getenv("PCAP_MCP_ALLOWED_DIRS", "").strip():
        raise ValueError("Set PCAP_MCP_ALLOWED_DIRS before running the baseline.")

    if evidence_mode not in {"legacy", "field"} or report_format not in {"narrative", "claims"}:
        raise ValueError("Invalid evidence mode or report format.")
    if report_format == "claims" and evidence_mode != "field":
        raise ValueError("Structured claims require field evidence.")

    if evidence_view not in {"structured", "flat"} or (
        evidence_view == "flat" and evidence_mode != "field"
    ):
        raise ValueError("Flat presentation requires field evidence.")
    if not 0 <= max_format_retries <= 3 or claims_response_format not in {"json", "prompt"}:
        raise ValueError("Invalid format-repair settings.")
    if not math.isfinite(temperature) or not 0 <= temperature <= 2 or not 0 <= seed <= 2**31 - 1:
        raise ValueError("Invalid temperature or seed.")

    manifest = manifest.resolve()
    cases = load_manifest(manifest)
    captures: dict[str, Path] = {}
    for case in cases:
        capture = (manifest.parent / case["capture"]).resolve()
        if not capture.is_file() or capture.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError(f"{case['id']}: capture file is missing or has the wrong extension.")
        captures[case["id"]] = capture
    output_dir.mkdir(parents=True, exist_ok=False)
    metadata = {
        "schema_version": 1,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_version": __version__,
        "python": platform.python_version(),
        "model": os.environ["OPENAI_MODEL"],
        # Retain comparability without saving endpoint credentials or query strings.
        "model_endpoint_sha256": hashlib.sha256(
            os.environ["OPENAI_BASE_URL"].encode("utf-8")
        ).hexdigest(),
        "settings": {key: os.getenv(key, "<default>") for key in SETTING_NAMES},
        "repeats": repeats,
        "max_calls": max_calls,
        "max_rounds": max_rounds,
        "request_timeout": request_timeout,
        "report_language": report_language,
        "evidence_mode": evidence_mode,
        "report_format": report_format,
        "evidence_view": evidence_view,
        "max_format_retries": max_format_retries,
        "claims_response_format": claims_response_format,
        "temperature": temperature,
        "seed": seed,
        "model_digest_declared": os.getenv("PCAP_MCP_MODEL_DIGEST"),
        "ollama_version_declared": os.getenv("PCAP_MCP_OLLAMA_VERSION"),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "cases": [
            {
                "id": case["id"],
                "capture_name": captures[case["id"]].name,
                "capture_sha256": _sha256(captures[case["id"]]),
                "goal": case["goal"],
                "required_tools": case.get("required_tools", []),
                "warning_tools": case.get("warning_tools", []),
                "forbidden_warning_tools": case.get("forbidden_warning_tools", []),
            }
            for case in cases
        ],
    }
    (output_dir / "experiment.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    trials: list[dict[str, Any]] = []
    for case in cases:
        for trial_number in range(1, repeats + 1):
            folder = output_dir / f"{case['id']}-{trial_number:03d}"
            folder.mkdir()
            command = [
                sys.executable,
                "-m",
                "pcap_mcp.agent",
                "--capture",
                str(captures[case["id"]]),
                "--goal",
                case["goal"],
                "--max-calls",
                str(max_calls),
                "--max-rounds",
                str(max_rounds),
                "--request-timeout",
                str(request_timeout),
                "--report-language",
                report_language,
                "--evidence-mode",
                evidence_mode,
                "--report-format",
                report_format,
                "--quiet",
                "--output",
                str(folder / "report.md"),
                "--evidence-json",
                str(folder / "evidence.json"),
            ]
            command += [
                "--evidence-view", evidence_view,
                "--max-format-retries", str(max_format_retries),
                "--claims-response-format", claims_response_format,
                "--temperature", str(temperature), "--seed", str(seed),
                "--audit-json", str(folder / "audit.json"),
            ]
            if report_format == "claims":
                command += ["--claims-json", str(folder / "claims.json")]
            started = time.monotonic()
            record: dict[str, Any] = {"case_id": case["id"], "trial": trial_number}
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                    timeout=max_rounds * request_timeout + max_calls * 60 + 30,
                )
                record["returncode"] = result.returncode
                if result.returncode == 0:
                    report = (folder / "report.md").read_text(encoding="utf-8")
                    evidence = json.loads((folder / "evidence.json").read_text(encoding="utf-8"))
                    if not isinstance(evidence, list):
                        raise ValueError("Evidence JSON must contain a list.")
                    record["checks"] = score(report, evidence, case)
                    record["tool_sequence"] = [item.get("tool") for item in evidence]
                    record["evidence_count"] = len(evidence)
                    record["status"] = "completed"

                else:
                    record["status"] = "failed"
                    error = result.stderr.replace(os.environ["OPENAI_API_KEY"], "[redacted]")
                    error = error.replace(os.environ["OPENAI_BASE_URL"], "[endpoint]")
                    record["error"] = error[-2000:]
            except (subprocess.TimeoutExpired, OSError, ValueError, KeyError) as exc:
                record["status"] = "failed"
                record["error"] = f"{type(exc).__name__}: {str(exc)[-500:]}"
            # Report failure never discards earlier tool checkpoints or source verification.
            evidence_path = folder / "evidence.json"
            if evidence_path.is_file():
                try:
                    partial = json.loads(evidence_path.read_text(encoding="utf-8"))
                    if not isinstance(partial, list):
                        raise ValueError("Evidence must be a list.")
                    record["tool_sequence"] = [item.get("tool") for item in partial]
                    record["evidence_count"] = len(partial)
                    record["evidence_checkpoint_present"] = True
                    if record["status"] != "completed":
                        record["partial_tool_checks"] = score("", partial, case)
                    if evidence_mode == "field":
                        from .claims import parse_claims
                        from .verify import verify_evidence

                        claims_path = folder / "claims.json"
                        claims = (
                            parse_claims(claims_path.read_text(encoding="utf-8"))
                            if record["status"] == "completed" and claims_path.is_file()
                            else None
                        )
                        verification = verify_evidence(captures[case["id"]], partial, claims)
                        (folder / "verification.json").write_text(
                            json.dumps(verification, ensure_ascii=False, indent=2), encoding="utf-8"
                        )
                        record["field_verification"] = {
                            key: verification[key]
                            for key in ("record_count", "matched_count", "all_records_match")
                        }
                        if claims is not None:
                            record["claim_verification"] = verification["claims"]
                except (RuntimeError, ValueError, OSError, KeyError, TypeError):
                    record["verification_error"] = "Saved evidence/source verification failed."
            else:
                record["evidence_checkpoint_present"] = False
            audit_path = folder / "audit.json"
            if audit_path.is_file():
                try:
                    audit = json.loads(audit_path.read_text(encoding="utf-8"))
                    record["format_diagnostics"] = {
                        key: audit.get(key) for key in (
                            "format_first_pass_valid", "format_attempts", "format_repair_requests",
                            "model_rounds", "claim_statistics",
                        )
                    }
                    record["evidence_views"] = audit.get("evidence_views", [])
                    record["audit_sha256"] = canonical_digest(audit)
                except (ValueError, OSError, TypeError):
                    record["audit_error"] = "Audit checkpoint could not be read."
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            (folder / "trial.json").write_text(
                json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            trials.append(record)
            print(f"{case['id']} trial {trial_number}/{repeats}: {record['status']}", flush=True)
    summary = {
        "experiment": metadata,
        "trials": trials,
        "totals": {
            "attempted": len(trials),
            "completed": sum(t["status"] == "completed" for t in trials),
            "failed": sum(t["status"] != "completed" for t in trials),
            "all_mechanical_checks_pass": sum(
                bool(t.get("checks")) and all(t["checks"].values()) for t in trials
            ),
        },
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Repeat PCAP Agent cases and retain trial records")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="A new, nonexistent directory"
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--max-calls", type=int, default=2)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--request-timeout", type=int, default=120)
    parser.add_argument("--report-language", choices=("auto", "zh", "en"), default="zh")
    parser.add_argument("--evidence-mode", choices=("legacy", "field"), default="field")
    parser.add_argument("--report-format", choices=("narrative", "claims"), default="narrative")
    parser.add_argument("--evidence-view", choices=("structured", "flat"), default="structured")
    parser.add_argument("--max-format-retries", type=int, default=1)
    parser.add_argument("--claims-response-format", choices=("prompt", "json"), default="json")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    try:
        summary = run(
            args.manifest,
            args.output_dir,
            repeats=args.repeats,
            max_calls=args.max_calls,
            max_rounds=args.max_rounds,
            request_timeout=args.request_timeout,
            report_language=args.report_language,
            evidence_mode=args.evidence_mode,
            report_format=args.report_format,
            evidence_view=args.evidence_view,
            max_format_retries=args.max_format_retries,
            claims_response_format=args.claims_response_format,
            temperature=args.temperature, seed=args.seed,
        )
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"pcap-mcp-baseline: {exc}\n")
    completed = sum(trial["status"] == "completed" for trial in summary["trials"])
    print(
        f"Completed {completed}/{len(summary['trials'])} trials; "
        f"see {args.output_dir / 'summary.json'}"
    )


if __name__ == "__main__":
    main()
