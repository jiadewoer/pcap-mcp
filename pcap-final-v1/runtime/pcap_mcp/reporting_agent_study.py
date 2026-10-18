"""Bounded actual MCP Agent comparison, with saved evidence and source re-extraction."""

from __future__ import annotations

import hashlib
import os
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .baseline import load_manifest, score
from .claims import check_claims, field_registry, parse_claims
from .lineage import FACT_TARGETS, MISSING, exact_equal, read_property
from .reporting import generate_report, valid_value
from .reporting_study import read_json
from .research import canonical_digest, write_json_atomic
from .verify import verify_evidence

VERSION = "reporting-agent-study-v1"


def fingerprints() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "agent.py",
            "reporting_agent_study.py",
            "reporting_study.py",
            "reporting.py",
            "claims.py",
            "lineage.py",
            "research.py",
            "verify.py",
            "server.py",
            "tshark.py",
            "provenance.py",
            "security.py",
            "evidence_io.py",
            "config.py",
            "baseline.py",
            "analysis.py",
        )
    }


def plan(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    rng = random.Random(protocol["order_seed"])
    rows = []
    for repeat in range(1, protocol["repeats"] + 1):
        block = [
            {"case_id": case["id"], "repeat": repeat, "model": model, "method": method}
            for case in protocol["cases"]
            for model in protocol["models"]
            for method in ("claims", "program")
        ]
        rng.shuffle(block)
        rows.extend(block)
    return [{**row, "run_id": f"run-{index:04d}"} for index, row in enumerate(rows, 1)]


def prepare(
    manifest: Path,
    output: Path,
    *,
    models: list[str],
    repeats: int = 1,
    order_seed: int = 2037,
    timeout: int = 120,
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        not models
        or len(set(models)) != len(models)
        or not 1 <= repeats <= 100
        or not 15 <= timeout <= 600
    ):
        raise ValueError("Invalid Agent models, repeats or timeout.")
    cases = load_manifest(manifest)
    captures = {}
    for case in cases:
        path = (manifest.resolve().parent / case["capture"]).resolve()
        if not path.is_file() or path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("Missing Agent capture.")
        captures[case["id"]] = {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    protocol = {
        "schema_version": 1,
        "study_version": VERSION,
        "cases": cases,
        "models": models,
        "captures": captures,
        "repeats": repeats,
        "order_seed": order_seed,
        "request_timeout": timeout,
        "max_calls": 2,
        "max_rounds": 3,
        "transport_retries": 0,
        "format_repairs": 0,
        "temperature": 0.0,
        "model_seed": 0,
        "reasoning_effort": "none",
        "evidence_view": "structured",
        "code_sha256": fingerprints(),
        "environment_declared": environment or {},
        "scope": "actual_agent_mechanics_and_source_fields_not_attack_success_or_prose_quality",
    }
    protocol["planned"] = plan(protocol)
    output.mkdir(parents=True, exist_ok=False)
    write_json_atomic(output / "protocol.json", protocol)
    return protocol


def validate(root: Path, *, source: bool = True) -> dict[str, Any]:
    protocol = read_json(root / "protocol.json")
    if (
        protocol.get("study_version") != VERSION
        or protocol["code_sha256"] != fingerprints()
        or protocol["planned"] != plan(protocol)
        or protocol["transport_retries"] != 0
        or protocol["format_repairs"] != 0
        or protocol["max_calls"] != 2
        or protocol["max_rounds"] != 3
        or protocol["reasoning_effort"] != "none"
    ):
        raise ValueError("Agent frozen protocol or code changed.")
    if source:
        for capture in protocol["captures"].values():
            path = Path(capture["path"])
            if (
                not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != capture["sha256"]
            ):
                raise ValueError("Agent source capture changed or disappeared.")
    return protocol


def coverage(evidence: list[dict[str, Any]], facts: list[dict[str, Any]]) -> dict[str, Any]:
    registry = field_registry(evidence)
    required = {
        (ref, prop)
        for ref, record in registry.items()
        if record["field"] == "http.user_agent"
        for prop in FACT_TARGETS
        if (actual := read_property(record, prop)) is not MISSING and valid_value(prop, actual)
    }
    emitted = {
        (fact["record"], fact["property"])
        for fact in facts
        if fact["record"] in registry
        and fact["property"] in FACT_TARGETS
        and exact_equal(fact["value"], read_property(registry[fact["record"]], fact["property"]))
    }
    return {
        "required": len(required),
        "covered": len(required & emitted),
        "complete": bool(required) and required <= emitted,
        "scope": "available_exported_user_agent_fields_not_entire_capture",
    }


def evaluate(
    folder: Path,
    protocol: dict[str, Any],
    row: dict[str, Any],
    *,
    source_recheck: bool = True,
    persist_verification: bool = True,
) -> dict[str, Any]:
    case = next(case for case in protocol["cases"] if case["id"] == row["case_id"])
    evidence_path = folder / "evidence.json"
    evidence = read_json(evidence_path) if evidence_path.is_file() else []
    report_path = folder / "report.md"
    text = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
    checks = score(text, evidence, case)
    facts = []
    output_valid, prose_status = False, None
    if row["method"] == "program" and (folder / "program-report.json").is_file():
        saved = read_json(folder / "program-report.json")
        # Replay closed facts independently; model prose is pinned by artifact hashes.
        generated = generate_report(evidence)
        for key in (
            "facts",
            "attributions",
            "source_payload_sha256",
            "unavailable",
            "excluded_evidence",
        ):
            if saved[key] != generated[key]:
                raise ValueError("Agent program facts disagree with saved evidence.")
        facts, prose_status = saved["facts"], saved["prose_status"]
        output_valid = prose_status == "valid_unverified"
    elif row["method"] == "claims" and (folder / "claims.json").is_file():
        proposed = parse_claims((folder / "claims.json").read_text(encoding="utf-8"))
        decisions = check_claims(proposed, evidence)
        facts = [item for item in decisions["facts"] if item["accepted"]]
        output_valid = True
    verification_path = folder / "verification.json"
    if source_recheck:
        verification = verify_evidence(Path(protocol["captures"][row["case_id"]]["path"]), evidence)
        if persist_verification:
            write_json_atomic(verification_path, verification)
    else:
        verification = read_json(verification_path) if verification_path.is_file() else {}
    return {
        "mechanical_checks": checks,
        "output_valid": output_valid,
        "prose_status": prose_status,
        "user_agent_field_coverage": coverage(evidence, facts),
        "source_record_count": verification.get("record_count", 0),
        "source_matched_count": verification.get("matched_count", 0),
        "source_all_records_match": bool(verification.get("record_count"))
        and verification.get("all_records_match") is True,
        "tool_sequence": [item["tool"] for item in evidence],
        "evidence_count": len(evidence),
        "scope": "mechanical_fields_only_prose_unverified",
    }


def artifact_hashes(folder: Path) -> dict[str, str]:
    return {
        name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
        for name in (
            "evidence.json",
            "audit.json",
            "report.md",
            "claims.json",
            "program-report.json",
            "verification.json",
        )
        if (folder / name).is_file()
    }


def summarize(protocol: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    totals = []
    for model in protocol["models"]:
        for method in ("claims", "program"):
            planned = [
                row
                for row in protocol["planned"]
                if (row["model"], row["method"]) == (model, method)
            ]
            selected = [row for row in rows if (row["model"], row["method"]) == (model, method)]
            totals.append(
                {
                    "model": model,
                    "method": method,
                    "planned": len(planned),
                    "attempted": len(selected),
                    "completed": sum(row["status"] == "completed" for row in selected),
                    "failed": sum(row["status"] == "failed" for row in selected),
                    "not_attempted_or_interrupted": len(planned)
                    - sum(row["status"] in {"completed", "failed"} for row in selected),
                    "complete_fields_and_source": sum(
                        row["status"] == "completed"
                        and row.get("evaluation", {})
                        .get("user_agent_field_coverage", {})
                        .get("complete", False)
                        and row["evaluation"]["source_all_records_match"]
                        for row in selected
                    ),
                    "model_rounds_observed": sum(row.get("model_rounds", 0) for row in selected),
                    "wall_seconds_all_attempts": round(
                        sum(row.get("duration_seconds", 0) for row in selected), 3
                    ),
                }
            )
    return {
        "schema_version": 1,
        "study_version": VERSION,
        "planned": len(protocol["planned"]),
        "totals": totals,
        "trials": rows,
        "scope": protocol["scope"],
    }


def save_summary(
    root: Path, protocol: dict[str, Any], rows: list[dict[str, Any]]
) -> dict[str, Any]:
    result = summarize(protocol, rows)
    write_json_atomic(root / "summary.json", result)
    lines = [
        "# 实际 MCP Agent 对照",
        "",
        "| 模型 | 方法 | 完成/计划 | 字段完整且重提取匹配/计划 |",
        "| --- | --- | --- | --- |",
    ]
    for row in result["totals"]:
        lines.append(
            f"| {row['model']} | {row['method']} | {row['completed']}/{row['planned']} | "
            f"{row['complete_fields_and_source']}/{row['planned']} |"
        )
    lines.extend(
        [
            "",
            "字段覆盖只评价已导出的 UA 记录，不评价整包覆盖、模型解释质量或攻击成功。",
            "两种模式的最终输出协议不同；这是架构对照，不是仅改变一行提示的因果实验。",
            "提示/解码/截断/工具选择/模型格式失败均保留。",
            "",
        ]
    )
    (root / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return result


def run(root: Path) -> dict[str, Any]:
    protocol = validate(root)
    if any((root / row["run_id"]).exists() for row in protocol["planned"]):
        raise ValueError("Agent study already attempted; use a new directory.")
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("OPENAI_BASE_URL"):
        raise ValueError("Set OPENAI_API_KEY and OPENAI_BASE_URL.")
    expected_endpoint = protocol["environment_declared"].get("endpoint_sha256")
    if (
        expected_endpoint
        and expected_endpoint
        != hashlib.sha256(os.getenv("OPENAI_BASE_URL", "").encode()).hexdigest()
    ):
        raise ValueError("Agent endpoint changed since preparation.")
    trials = []
    for row in protocol["planned"]:
        case = next(case for case in protocol["cases"] if case["id"] == row["case_id"])
        folder = root / row["run_id"]
        folder.mkdir()
        capture = protocol["captures"][row["case_id"]]["path"]
        command = [
            sys.executable,
            "-m",
            "pcap_mcp.agent",
            "--capture",
            capture,
            "--goal",
            case["goal"],
            "--max-calls",
            "2",
            "--max-rounds",
            "3",
            "--request-timeout",
            str(protocol["request_timeout"]),
            "--evidence-mode",
            "field",
            "--evidence-view",
            "structured",
            "--report-language",
            "zh",
            "--report-format",
            row["method"],
            "--max-format-retries",
            "0",
            "--transport-retries",
            "0",
            "--reasoning-effort",
            "none",
            "--temperature",
            "0",
            "--seed",
            "0",
            "--output",
            str(folder / "report.md"),
            "--evidence-json",
            str(folder / "evidence.json"),
            "--audit-json",
            str(folder / "audit.json"),
            "--quiet",
        ]
        command += (
            ["--claims-json", str(folder / "claims.json")]
            if row["method"] == "claims"
            else ["--program-json", str(folder / "program-report.json")]
        )
        write_json_atomic(folder / "command.json", command)
        trial = {**row, "status": "started", "command_sha256": canonical_digest(command)}
        write_json_atomic(folder / "trial.json", trial)
        environment = dict(os.environ)
        environment["OPENAI_MODEL"] = row["model"]
        environment["PCAP_MCP_ALLOWED_DIRS"] = str(Path(capture).parent)
        started = time.monotonic()
        try:
            process = subprocess.run(
                command,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=3 * protocol["request_timeout"] + 2 * 60 + 30,
            )
            trial["returncode"] = process.returncode
            trial["status"] = "completed" if process.returncode == 0 else "failed"
            if process.returncode != 0:
                trial["failure_label"] = "agent_process_failure"
        except subprocess.TimeoutExpired:
            trial.update(status="failed", failure_label="outer_process_timeout")
        except OSError as exc:
            trial.update(
                status="failed", failure_label="process_launch_error", error_type=type(exc).__name__
            )
        try:
            trial["evaluation"] = evaluate(folder, protocol, row)
            if trial["status"] == "completed" and not (
                trial["evaluation"]["output_valid"]
                and trial["evaluation"]["source_all_records_match"]
                and all(trial["evaluation"]["mechanical_checks"].values())
            ):
                trial.update(status="failed", failure_label="report_or_mechanics_or_source_failure")
        except (ValueError, RuntimeError, OSError, KeyError, TypeError) as exc:
            trial.update(
                status="failed",
                failure_label="evidence_or_source_check_failure",
                error_type=type(exc).__name__,
            )
        audit_path = folder / "audit.json"
        if audit_path.is_file():
            audit = read_json(audit_path)
            trial["model_rounds"] = audit.get("model_rounds", 0)
            trial["agent_error_type"] = audit.get("failure_type")
        trial["artifact_sha256"] = artifact_hashes(folder)
        trial["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json_atomic(folder / "trial.json", trial)
        trials.append(trial)
        save_summary(root, protocol, trials)
        print(
            f"{row['run_id']} {row['case_id']} {row['model']} {row['method']}: {trial['status']}",
            flush=True,
        )
    return summarize(protocol, trials)


def replay(root: Path, output: Path | None = None, *, reextract: bool = False) -> dict[str, Any]:
    protocol = validate(root, source=reextract)
    trials = []
    for row in protocol["planned"]:
        folder = root / row["run_id"]
        if not (folder / "trial.json").is_file():
            continue
        trial = read_json(folder / "trial.json")
        if any(trial.get(key) != value for key, value in row.items()):
            raise ValueError("Agent trial metadata changed.")
        if trial["command_sha256"] != canonical_digest(read_json(folder / "command.json")):
            raise ValueError("Agent command changed.")
        if trial.get("artifact_sha256", {}) != artifact_hashes(folder):
            raise ValueError("Agent evidence, report, audit or verification changed.")
        if "evaluation" in trial:
            evaluation = evaluate(
                folder, protocol, row, source_recheck=reextract, persist_verification=False
            )
            if trial["evaluation"] != evaluation:
                raise ValueError("Agent fixed artifact evaluation changed.")
        trials.append(trial)
    result = summarize(protocol, trials)
    if output:
        if output.exists():
            raise ValueError("Use a new Agent analysis output file.")
        write_json_atomic(output, result)
    return result
