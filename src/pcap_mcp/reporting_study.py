"""Freeze, run and replay development/heldout report studies without changing old checkers."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import time
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import lineage as lab
from .claims import PROPERTIES
from .reporting import PROGRAM_PROMPT, as_proposal, generate_report, render_report, valid_value
from .research import canonical_digest, write_json_atomic

VERSION = "reporting-study-v1"
ARMS = ("original", "availability", "completeness", "both")
AVAILABILITY = """
AVAILABILITY CHECK: Inspect each requested counter in its own record before labeling
lineage. A missing, boolean, negative, floating-point or string counter is unavailable.
If either dot counter is unavailable, middle_dot_origin is unknown. If the control
counter is unavailable, control_removal_observed is unknown. Never infer zero from
absence, display text, another field or an upstream decoder count.
"""
COMPLETENESS = """
COMPLETENESS CHECK: For every User-Agent occurrence, emit one fact for EACH available
present, display_value, injection_kinds, value_basis,
input_decoding.tshark_display_replacement_characters,
transformations.unicode_controls_removed, transformations.middle_dots_inserted_by_server,
transformations.middle_dots_in_decoded_source. Preserve [] when empty. Do not invent
missing or invalid values. Include exactly one middle_dot_origin and one
control_removal_observed attribution for each occurrence, including unknown labels.
Check occurrence references and completeness internally before returning the JSON object.
"""

# Exact native-types contract from type-study v1; old addon files remain unchanged.
NATIVE_TYPES = """
OUTPUT TYPE CONTRACT (applies to serialization, without changing observations):
Copy each available fact's value with its original JSON type. Never stringify a
boolean, number or array. true is a boolean; "true" is a different string.
0 is an integer; "0" is a different string. [] is an array; "[]" is a different string.
Required types by property:
- present: JSON boolean true or false, without quotation marks.
- input_decoding.header_envelope_removed: JSON boolean.
- transformations.redaction_changed and transformations.uri_suffix_removed: JSON booleans.
- display_value and value_basis: JSON strings.
- injection_kinds: JSON array of strings, including [] when empty.
- input_decoding.tshark_display_replacement_characters: nonnegative JSON integer.
- transformations.unicode_controls_removed: nonnegative JSON integer.
- transformations.middle_dots_inserted_by_server: nonnegative JSON integer.
- transformations.middle_dots_in_decoded_source: nonnegative JSON integer.
Do not invent a value for a missing property, and do not substitute a value from
another record. Do not translate property names, references or enum values.
Every attribution is ONE {record,property,value} item, with a string enum value;
do not combine middle_dot_origin and control_removal_observed into one item.
Every hypothesis basis is an array of reference STRINGS, not objects.
Type illustrations only; NEVER copy their references or values into your answer:
{"record":"E02/F999:http.user_agent/0","property":"present","value":true}
{"record":"E02/F999:http.user_agent/0","property":"injection_kinds","value":[]}
{"record":"E02/F999:http.user_agent/0",
 "property":"transformations.unicode_controls_removed","value":2}
{"text":"仅示范引用结构","basis":["E02/F999:http.user_agent/0"]}
Before returning, check these types and the requested structure internally.
Return only the JSON object. Preserve the supplied values and distinguish unknown
lineage from a recorded zero. Do not repair values to satisfy an imagined answer.
"""


def strict_json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key.")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ValueError("Nonfinite JSON value.")

    value = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
    json.dumps(value, allow_nan=False)  # also reject finite-notation float overflow
    return value


def read_json(path: Path) -> Any:
    return strict_json(path.read_text(encoding="utf-8-sig"))


def fingerprints() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "reporting_study.py",
            "reporting.py",
            "lineage.py",
            "claims.py",
            "research.py",
            "evidence_io.py",
        )
    }


def validate_heldout(suite: dict[str, Any]) -> None:
    if suite.get("suite") != "reporting-heldout-v1" or not suite.get("cases"):
        raise ValueError("Unsupported or empty heldout suite.")
    ids = set()
    for case in suite["cases"]:
        if case["id"] in ids:
            raise ValueError("Duplicate heldout case.")
        ids.add(case["id"])
        records = {record["record_id"]: record for record in case["records"]}
        if len(records) != len(case["records"]) or set(records) != set(case["slots"]):
            raise ValueError("Ambiguous heldout records.")
        if set(case["gold"]) != set(case["slots"].values()):
            raise ValueError("Heldout gold slots disagree.")
        # Validate declarations, never generate a gold label with the checker.
        for rid, record in records.items():
            gold = case["gold"][case["slots"][rid]]
            for prop in PROPERTIES:
                actual = lab.read_property(record, prop)
                available = actual is not lab.MISSING and valid_value(prop, actual)
                if available != (prop in gold) or (
                    available and not lab.exact_equal(actual, gold[prop])
                ):
                    raise ValueError("Declared heldout fact differs from the input.")
            if gold.get("middle_dot_origin") not in {
                "none",
                "analysis_program",
                "decoded_source",
                "both",
                "unknown",
            } or gold.get("control_removal_observed") not in {"no", "yes", "unknown"}:
                raise ValueError("Invalid independently declared lineage label.")
        generate_report(lab.evidence_for(case))  # reference/envelope boundary validation


def suites(root: Path) -> dict[str, Any]:
    development = lab.build_suite(root / "benchmarks/lineage")
    heldout = read_json(root / "benchmarks/reporting/heldout-suite.json")
    validate_heldout(heldout)
    old_families = {case["pair"] for case in development["cases"]}
    new_families = {case["family"] for case in heldout["cases"]}
    if old_families & new_families:
        raise ValueError("Development and heldout family labels overlap.")
    return {"development": development, "heldout": heldout}


def prompt(case: dict[str, Any], view: str, arm: str) -> list[dict[str, Any]]:
    messages = lab.model_messages(case, view)
    if arm == "program":
        messages[0]["content"] = PROGRAM_PROMPT
    else:
        if arm not in ARMS:
            raise ValueError("Unknown prompt arm.")
        messages[0]["content"] += NATIVE_TYPES
        if arm in {"availability", "both"}:
            messages[0]["content"] += AVAILABILITY
        if arm in {"completeness", "both"}:
            messages[0]["content"] += COMPLETENESS
    return messages


def schedule(protocol: dict[str, Any], suite: dict[str, Any]) -> list[dict[str, Any]]:
    rng = random.Random(protocol["order_seed"])
    planned = []
    for repeat in range(1, protocol["repeats"] + 1):
        cases = list(suite["cases"])
        rng.shuffle(cases)
        for case in cases:
            block = [
                {
                    "case_id": case["id"],
                    "family": case.get("family", case.get("pair")),
                    "repeat": repeat,
                    "view": view,
                    "model": model,
                    "method": method,
                }
                for model in protocol["models"]
                for view in ("structured", "flat")
                for method in protocol["methods"]
            ]
            rng.shuffle(block)
            planned.extend(block)
    return [{**row, "run_id": f"run-{index:04d}"} for index, row in enumerate(planned, 1)]


def request_for(
    protocol: dict[str, Any], case: dict[str, Any], row: dict[str, Any]
) -> dict[str, Any]:
    arm = protocol["methods"][row["method"]]
    return {
        "model": row["model"],
        "messages": prompt(case, row["view"], arm),
        "temperature": 0.0,
        "seed": protocol["model_seed"],
        "response_format": {"type": "json_object"},
        "reasoning_effort": "none",
    }


def exact(evaluation: dict[str, Any], gate: str = "off") -> bool:
    return all(
        evaluation["gates"][gate][kind]["all_required_correct"]
        and evaluation["gates"][gate][kind]["defined_incorrect"] == 0
        and evaluation["gates"][gate][kind]["out_of_scope"] == 0
        for kind in ("facts", "attributions")
    )


def program_baseline(suite: dict[str, Any]) -> dict[str, Any]:
    results = {}
    for case in suite["cases"]:
        report = generate_report(lab.evidence_for(case))
        results[case["id"]] = lab.evaluate_proposal(as_proposal(report), case)
    return {
        "scope": "closed_record_questions_no_model_no_prose_quality",
        "cases": results,
        "exact_cases": sum(exact(item) for item in results.values()),
        "planned_cases": len(results),
    }


def summarize(
    protocol: dict[str, Any], suite: dict[str, Any], trials: list[dict[str, Any]]
) -> dict[str, Any]:
    cases = {case["id"]: case for case in suite["cases"]}
    by_id = {row["run_id"]: row for row in trials}
    totals = []
    for model in protocol["models"]:
        for method in protocol["methods"]:
            for view in ("structured", "flat"):
                planned = [
                    row
                    for row in protocol["planned"]
                    if (row["model"], row["method"], row["view"]) == (model, method, view)
                ]
                observed = [by_id[row["run_id"]] for row in planned if row["run_id"] in by_id]
                for gate in lab.GATES:
                    total: dict[str, Any] = {
                        "model": model,
                        "method": method,
                        "view": view,
                        "gate": gate,
                        "planned": len(planned),
                        "attempted": len(observed),
                        "completed": sum(row["status"] == "completed" for row in observed),
                        "failed": sum(row["status"] == "failed" for row in observed),
                        "not_attempted_or_interrupted": len(planned)
                        - sum(row["status"] in {"completed", "failed"} for row in observed),
                        "exact_with_valid_prose_or_proposal": sum(
                            row["status"] == "completed" and exact(row["evaluation"], gate)
                            for row in observed
                        ),
                        "failure_labels": dict(
                            Counter(
                                row.get("failure_label", "interrupted")
                                for row in observed
                                if row["status"] != "completed"
                            )
                        ),
                        "wall_seconds_all_attempts": round(
                            sum(row.get("duration_seconds", 0) for row in observed), 3
                        ),
                    }
                    # Program facts exist without model prose, including API/format failures.
                    scores = [
                        row["evaluation"]["gates"][gate] for row in observed if "evaluation" in row
                    ]
                    for kind, properties in (
                        ("facts", lab.FACT_TARGETS),
                        ("attributions", lab.ATTRIBUTION_TARGETS),
                    ):
                        total[kind] = {
                            key: sum(score[kind][key] for score in scores)
                            for key in (
                                "emitted",
                                "correct",
                                "defined_incorrect",
                                "out_of_scope",
                                "covered",
                            )
                        }
                        total[kind]["required_all_planned"] = sum(
                            prop in values
                            for row in planned
                            for values in cases[row["case_id"]]["gold"].values()
                            for prop in properties
                        )
                    totals.append(total)
    return {
        "schema_version": 1,
        "study_version": VERSION,
        "phase": protocol["phase"],
        "planned": len(protocol["planned"]),
        "totals": totals,
        "trials": trials,
        "scope": "descriptive_curated_record_transfer_no_population_or_semantic_claim",
    }


def report_text(summary: dict[str, Any]) -> str:
    lines = [
        "# 报告生成对照",
        "",
        f"阶段：{summary['phase']}；计划请求：{summary['planned']}。",
        "",
        "| 模型 | 方法 | 表示 | 合法输出/计划 | 字段覆盖 | 来源覆盖 | "
        "原始错误归因 | 完整用例/计划 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["totals"]:
        if row["gate"] != "off":
            continue
        f, a = row["facts"], row["attributions"]
        lines.append(
            f"| {row['model']} | {row['method']} | {row['view']} | "
            f"{row['completed']}/{row['planned']} | {f['covered']}/{f['required_all_planned']} | "
            f"{a['covered']}/{a['required_all_planned']} | {a['defined_incorrect']} | "
            f"{row['exact_with_valid_prose_or_proposal']}/{row['planned']} |"
        )
    lines.extend(
        [
            "",
            "失败、未尝试和中断保留在计划分母。program 的字段覆盖可以在模型正文失败时保留；",
            "完整用例列要求模型正文通过结构校验，仍不表示正文语义正确。三个 gate 复用同一输出。",
            "",
            "留出集是新组合与边界记录，部分沿用开发集的基础计数机制；不是外部盲测抓包。",
            "重复请求、同一用例中的属性和记录均不是独立样本。不作显著性或攻击成功率结论。",
            "",
        ]
    )
    return "\n".join(lines)


def freeze(
    root: Path,
    output: Path,
    *,
    phase: str,
    models: list[str],
    repeats: int = 1,
    order_seed: int = 2037,
    timeout: int = 120,
    selected: dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        phase not in {"development", "heldout"}
        or not 1 <= repeats <= 100
        or not 15 <= timeout <= 600
        or not models
        or len(set(models)) != len(models)
        or any(not name.strip() or len(name) > 200 for name in models)
    ):
        raise ValueError("Invalid phase, models, repeats or timeout.")
    all_suites = suites(root)
    if phase == "heldout" and (
        not selected
        or selected.get("arm") not in ARMS
        or selected.get("source_phase") != "development"
    ):
        raise ValueError("Heldout requires a selection derived from a completed development study.")
    if phase == "development":
        methods = {arm: arm for arm in ARMS}
    else:
        assert selected is not None
        methods = {"legacy": "original", "selected": selected["arm"], "program": "program"}
    source = all_suites[phase]
    protocol: dict[str, Any] = {
        "schema_version": 1,
        "study_version": VERSION,
        "phase": phase,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "models": models,
        "methods": methods,
        "repeats": repeats,
        "order_seed": order_seed,
        "model_seed": 0,
        "timeout_seconds": timeout,
        "suite_sha256": canonical_digest(source),
        "code_sha256": fingerprints(),
        "selected": selected,
        "transport_retries": 0,
        "format_repairs": 0,
        "type_coercion": False,
        "reasoning_effort": "none",
        "environment_declared": environment or {},
        "explicit_context_or_token_budget": False,
        "source_scope": "frozen_tool_records_not_actual_agent_or_new_capture_verification",
    }
    protocol["planned"] = schedule(protocol, source)
    output.mkdir(parents=True, exist_ok=False)
    write_json_atomic(output / "suite.json", source)
    write_json_atomic(output / "protocol.json", protocol)
    write_json_atomic(output / "program-baseline.json", program_baseline(source))
    save_summary(output, protocol, source, [])
    return protocol


def validate_study(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol, suite = read_json(root / "protocol.json"), read_json(root / "suite.json")
    if protocol.get("study_version") != VERSION or protocol["code_sha256"] != fingerprints():
        raise ValueError("Study/checker code changed after freeze.")
    if canonical_digest(suite) != protocol["suite_sha256"]:
        raise ValueError("Frozen suite changed.")
    if protocol["phase"] == "development":
        lab.validate_suite(suite)
        if protocol["methods"] != {arm: arm for arm in ARMS}:
            raise ValueError("Development arms changed.")
    elif protocol["phase"] == "heldout":
        validate_heldout(suite)
        if protocol["methods"] != {
            "legacy": "original",
            "selected": protocol["selected"]["arm"],
            "program": "program",
        }:
            raise ValueError("Heldout selection changed.")
    else:
        raise ValueError("Invalid frozen phase.")
    if (
        protocol["planned"] != schedule(protocol, suite)
        or protocol["transport_retries"] != 0
        or protocol["format_repairs"] != 0
        or protocol["type_coercion"] is not False
    ):
        raise ValueError("Schedule or protocol constraints changed.")
    return protocol, suite


def save_summary(
    root: Path, protocol: dict[str, Any], suite: dict[str, Any], trials: list[dict[str, Any]]
) -> dict[str, Any]:
    result = summarize(protocol, suite, trials)
    write_json_atomic(root / "summary.json", result)
    (root / "report.md").write_text(report_text(result), encoding="utf-8")
    return result


async def sdk_call(client: Any, body: dict[str, Any]) -> Any:
    args = deepcopy(body)
    args["extra_body"] = {"reasoning_effort": args.pop("reasoning_effort")}
    return await client.chat.completions.create(**args)


async def run(root: Path, client: Any, *, sanitize: Any = lambda text: text) -> dict[str, Any]:
    protocol, suite = validate_study(root)
    if any((root / row["run_id"]).exists() for row in protocol["planned"]):
        raise ValueError(
            "Study already attempted; use a new frozen directory, never overwrite trials."
        )
    cases = {case["id"]: case for case in suite["cases"]}
    trials = []
    for row in protocol["planned"]:
        case = cases[row["case_id"]]
        folder = root / row["run_id"]
        folder.mkdir()
        body = request_for(protocol, case, row)
        write_json_atomic(folder / "request.json", body)
        trial = {**row, "status": "started", "request_sha256": canonical_digest(body)}
        if row["method"] == "program":
            generated = generate_report(lab.evidence_for(case))
            trial["evaluation"] = lab.evaluate_proposal(as_proposal(generated), case)
            write_json_atomic(folder / "program-report.json", generated)
        write_json_atomic(folder / "trial.json", trial)
        started, stage = time.monotonic(), "request"
        try:
            response = await sdk_call(client, body)
            stage = "processing"
            choices = getattr(response, "choices", None) or []
            message = choices[0].message if choices else None
            content = (getattr(message, "content", None) or "") if message else ""
            stored = sanitize(content)
            reasoning = (
                (
                    getattr(message, "reasoning", None)
                    or getattr(message, "reasoning_content", None)
                    or ""
                )
                if message
                else ""
            )
            trial["response_metadata"] = {
                "choices": len(choices),
                "returned_model": sanitize(getattr(response, "model", "") or ""),
                "finish_reason": getattr(choices[0], "finish_reason", None) if choices else None,
                "reasoning_characters": len(reasoning) if isinstance(reasoning, str) else None,
                "usage": response.usage.model_dump()
                if hasattr(getattr(response, "usage", None), "model_dump")
                else None,
            }
            write_json_atomic(
                folder / "response.json",
                {
                    "text": stored[:50_000],
                    "original_characters": len(content),
                    "original_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "stored_copy_changed": stored != content,
                    "stored_copy_truncated": len(stored) > 50_000,
                    **trial["response_metadata"],
                },
            )
            if stored != content or len(stored) > 50_000:
                trial.update(status="failed", failure_label="response_storage_changed_or_truncated")
            elif row["method"] == "program":
                generated = generate_report(lab.evidence_for(case), content)
                write_json_atomic(folder / "program-report.json", generated)
                (folder / "program-report.md").write_text(
                    render_report(generated), encoding="utf-8"
                )
                trial["prose_status"] = generated["prose_status"]
                trial.update(
                    status="completed"
                    if generated["prose_status"] == "valid_unverified"
                    else "failed"
                )
                if trial["status"] == "failed":
                    trial["failure_label"] = (
                        "empty_content" if not content.strip() else "invalid_prose_schema"
                    )
            elif not content.strip():
                trial.update(status="failed", failure_label="empty_content")
            else:
                try:
                    proposal = lab.parse_proposal(content)
                except (ValueError, TypeError, OverflowError, RecursionError):
                    trial.update(status="failed", failure_label="invalid_proposal_schema")
                else:
                    trial["evaluation"] = lab.evaluate_proposal(proposal, case)
                    write_json_atomic(folder / "proposal.json", proposal)
                    trial.update(status="completed")
        except Exception as exc:
            trial.update(
                status="failed",
                failure_label="api_error" if stage == "request" else "processing_error",
                error_type=type(exc).__name__,
            )
            status = getattr(exc, "status_code", None)
            if type(status) is int:
                trial["http_status"] = status
        trial["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json_atomic(folder / "trial.json", trial)
        trials.append(trial)
        save_summary(root, protocol, suite, trials)
        print(
            f"{row['run_id']} {row['model']} {row['method']} {row['view']}: {trial['status']}",
            flush=True,
        )
    return summarize(protocol, suite, trials)


def replay(root: Path, output: Path | None = None) -> dict[str, Any]:
    protocol, suite = validate_study(root)
    cases = {case["id"]: case for case in suite["cases"]}
    trials = []
    for row in protocol["planned"]:
        folder = root / row["run_id"]
        if not (folder / "trial.json").is_file():
            continue
        trial = read_json(folder / "trial.json")
        if trial.get("status") not in {"started", "completed", "failed"}:
            raise ValueError("Invalid trial status.")
        if any(trial.get(key) != value for key, value in row.items()):
            raise ValueError("Trial metadata changed.")
        body = request_for(protocol, cases[row["case_id"]], row)
        if read_json(folder / "request.json") != body or trial[
            "request_sha256"
        ] != canonical_digest(body):
            raise ValueError("Frozen model input changed.")
        response_path = folder / "response.json"
        response = read_json(response_path) if response_path.is_file() else None
        if (
            response
            and not response["stored_copy_changed"]
            and not response["stored_copy_truncated"]
        ):
            if (
                len(response["text"]) != response["original_characters"]
                or hashlib.sha256(response["text"].encode("utf-8")).hexdigest()
                != response["original_sha256"]
            ):
                raise ValueError("Stored response changed.")
        if trial["status"] in {"completed", "failed"} and response:
            expected_label: str | None
            changed = response["stored_copy_changed"] or response["stored_copy_truncated"]
            if changed:
                expected_status, expected_label = "failed", "response_storage_changed_or_truncated"
            elif row["method"] == "program":
                status = generate_report(lab.evidence_for(cases[row["case_id"]]), response["text"])[
                    "prose_status"
                ]
                expected_status = "completed" if status == "valid_unverified" else "failed"
                expected_label = (
                    None
                    if expected_status == "completed"
                    else (
                        "empty_content" if not response["text"].strip() else "invalid_prose_schema"
                    )
                )
            elif not response["text"].strip():
                expected_status, expected_label = "failed", "empty_content"
            else:
                try:
                    lab.parse_proposal(response["text"])
                except (ValueError, TypeError, OverflowError, RecursionError):
                    expected_status, expected_label = "failed", "invalid_proposal_schema"
                else:
                    expected_status, expected_label = "completed", None
            if trial["status"] != expected_status or trial.get("failure_label") != expected_label:
                raise ValueError("Trial completion/failure disagrees with fixed response.")
        elif trial["status"] == "completed":
            raise ValueError("Completed trial has no response.")
        if row["method"] == "program":
            if trial.get("prose_status"):
                if (
                    not response
                    or response["stored_copy_changed"]
                    or response["stored_copy_truncated"]
                ):
                    raise ValueError("Program prose cannot be replayed from altered storage.")
                generated = generate_report(
                    lab.evidence_for(cases[row["case_id"]]), response["text"]
                )
                if generated["prose_status"] != trial["prose_status"]:
                    raise ValueError("Program prose status changed.")
            else:
                generated = generate_report(lab.evidence_for(cases[row["case_id"]]))
            if read_json(folder / "program-report.json") != generated:
                raise ValueError("Program report changed.")
            evaluation = lab.evaluate_proposal(as_proposal(generated), cases[row["case_id"]])
            if "evaluation" in trial and trial["evaluation"] != evaluation:
                raise ValueError("Program evaluation changed.")
            trial["evaluation"] = evaluation
        elif trial["status"] == "completed":
            if not response or response["stored_copy_changed"] or response["stored_copy_truncated"]:
                raise ValueError("Completed proposal lacks intact response storage.")
            proposal = lab.parse_proposal(response["text"])
            if read_json(folder / "proposal.json") != proposal:
                raise ValueError("Proposal differs from the fixed model output.")
            evaluation = lab.evaluate_proposal(proposal, cases[row["case_id"]])
            if trial["evaluation"] != evaluation:
                raise ValueError("Evaluation changed.")
            trial["evaluation"] = evaluation
        trials.append(trial)
    result = summarize(protocol, suite, trials)
    if output:
        if output.exists():
            raise ValueError("Use a new analysis output file.")
        write_json_atomic(output, result)
    return result


def select(root: Path) -> dict[str, Any]:
    protocol, _ = validate_study(root)
    if protocol["phase"] != "development":
        raise ValueError("Prompt selection is only allowed from development results.")
    summary = replay(root)
    if len(summary["trials"]) != len(protocol["planned"]) or any(
        row["status"] not in {"completed", "failed"} for row in summary["trials"]
    ):
        raise ValueError("Finish all planned development attempts before selection.")
    ranking = []
    for index, arm in enumerate(ARMS):
        rows = [row for row in summary["totals"] if row["method"] == arm and row["gate"] == "off"]
        ranking.append(
            (
                sum(row["exact_with_valid_prose_or_proposal"] for row in rows),
                sum(row["facts"]["covered"] + row["attributions"]["covered"] for row in rows),
                -sum(
                    row["facts"]["defined_incorrect"]
                    + row["attributions"]["defined_incorrect"]
                    + row["facts"]["out_of_scope"]
                    + row["attributions"]["out_of_scope"]
                    for row in rows
                ),
                -index,
                arm,
            )
        )
    winner = max(ranking)[-1]
    return {
        "arm": winner,
        "source_phase": "development",
        "source_protocol_sha256": canonical_digest(protocol),
        "source_summary_sha256": canonical_digest(summary),
        "rule": (
            "maximize planned exact cases, then closed coverage, then minimize errors; "
            "tie favors simpler arm"
        ),
        "ranking": [list(row) for row in sorted(ranking, reverse=True)],
        "scope": "descriptive_selection_not_statistical_evidence",
    }


def check(root: Path, output: Path | None = None) -> dict[str, Any]:
    loaded = suites(root)
    results = {phase: program_baseline(suite) for phase, suite in loaded.items()}
    if any(row["exact_cases"] != row["planned_cases"] for row in results.values()):
        raise ValueError("Program report disagrees with an independently declared gold answer.")
    result = {
        "study_version": VERSION,
        "no_model_calls": True,
        "program_baselines": results,
        "suite_sha256": {k: canonical_digest(v) for k, v in loaded.items()},
        "scope": "closed_properties_of_curated_tool_records_not_live_agent_or_prose",
    }
    if output:
        output.mkdir(parents=True, exist_ok=False)
        write_json_atomic(output / "check.json", result)
        case = loaded["heldout"]["cases"][2]
        sample = generate_report(lab.evidence_for(case))
        write_json_atomic(output / "example-program-report.json", sample)
        (output / "example-program-report.md").write_text(render_report(sample), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare/run/replay report-generation studies")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true")
    actions.add_argument("--prepare", action="store_true")
    actions.add_argument("--run", type=Path)
    actions.add_argument("--replay", type=Path)
    actions.add_argument("--select", type=Path)
    actions.add_argument("--prepare-agent", type=Path, metavar="MANIFEST")
    actions.add_argument("--run-agent", type=Path)
    actions.add_argument("--replay-agent", type=Path)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--phase", choices=("development", "heldout"), default="development")
    parser.add_argument("--models", nargs="+")
    parser.add_argument("--model-identities", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--analysis-output", type=Path)
    parser.add_argument("--development-study", type=Path)
    parser.add_argument("--reextract", action="store_true")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--order-seed", type=int, default=2037)
    parser.add_argument("--request-timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        declared: dict[str, Any] = {"ollama_version": os.getenv("PCAP_MCP_OLLAMA_VERSION", "")}
        if args.model_identities:
            identities = read_json(args.model_identities)
            if (
                not isinstance(identities, dict)
                or set(identities) != set(args.models or [])
                or any(
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)
                    for digest in identities.values()
                )
            ):
                raise ValueError(
                    "Model identity file must map every selected name to its SHA-256 digest."
                )
            declared["model_digest_map"] = identities
            declared["identities_file_sha256"] = hashlib.sha256(
                args.model_identities.read_bytes()
            ).hexdigest()
        declared["endpoint_sha256"] = hashlib.sha256(
            os.getenv("OPENAI_BASE_URL", "").encode()
        ).hexdigest()
        if args.prepare_agent or args.run_agent or args.replay_agent:
            from . import reporting_agent_study as agent_study

            if args.prepare_agent:
                if not args.output_dir or not args.models:
                    raise ValueError("--prepare-agent requires --models and --output-dir.")
                protocol = agent_study.prepare(
                    args.prepare_agent,
                    args.output_dir,
                    models=args.models,
                    repeats=args.repeats,
                    order_seed=args.order_seed,
                    timeout=args.request_timeout,
                    environment=declared,
                )
                print(f"Prepared {len(protocol['planned'])} Agent investigations; no model calls.")
            elif args.run_agent:
                agent_study.run(args.run_agent)
            else:
                agent_study.replay(
                    args.replay_agent, args.analysis_output, reextract=args.reextract
                )
                print("Agent fixed output replay complete; no model calls.")
        elif args.check:
            result = check(args.project, args.output_dir)
            print(
                json.dumps(
                    {
                        phase: {key: row[key] for key in ("exact_cases", "planned_cases")}
                        for phase, row in result["program_baselines"].items()
                    },
                    ensure_ascii=False,
                )
            )
        elif args.prepare:
            if not args.output_dir or not args.models:
                raise ValueError("--prepare requires --output-dir and --models.")
            selected = select(args.development_study) if args.development_study else None
            result = freeze(
                args.project,
                args.output_dir,
                phase=args.phase,
                models=args.models,
                repeats=args.repeats,
                order_seed=args.order_seed,
                timeout=args.request_timeout,
                selected=selected,
                environment={
                    **declared,
                    "model_digest": os.getenv("PCAP_MCP_MODEL_DIGEST", "")
                    if len(args.models) == 1
                    else "",
                    "ollama_version": os.getenv("PCAP_MCP_OLLAMA_VERSION", ""),
                    "multi_model_digest_note": (
                        "model identity is declared; pin each installed model before running"
                    ),
                },
            )
            print(f"Prepared {len(result['planned'])} requests; no model calls: {args.output_dir}")
        elif args.replay:
            replay(args.replay, args.analysis_output)
            print("Fixed output replay complete; no model calls.")
        elif args.select:
            selected = select(args.select)
            if args.analysis_output:
                if args.analysis_output.exists():
                    raise ValueError("Use a new selection output file.")
                write_json_atomic(args.analysis_output, selected)
            print(json.dumps(selected, ensure_ascii=False, indent=2))
        else:
            from openai import AsyncOpenAI

            protocol, _ = validate_study(args.run)
            key, url = os.getenv("OPENAI_API_KEY", ""), os.getenv("OPENAI_BASE_URL", "")
            if not key or not url:
                raise ValueError("Set OPENAI_API_KEY and OPENAI_BASE_URL.")
            expected_endpoint = protocol["environment_declared"].get("endpoint_sha256")
            if expected_endpoint and expected_endpoint != hashlib.sha256(url.encode()).hexdigest():
                raise ValueError(
                    "Endpoint changed since preparation; prepare under the intended endpoint."
                )

            def sanitize(text: str) -> str:
                return text.replace(key, "[redacted]").replace(url, "[redacted]")

            async def execute() -> None:
                async with AsyncOpenAI(
                    api_key=key, base_url=url, max_retries=0, timeout=protocol["timeout_seconds"]
                ) as client:
                    await run(args.run, client, sanitize=sanitize)

            asyncio.run(execute())
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"reporting-study: {exc}\n")


if __name__ == "__main__":
    main()
