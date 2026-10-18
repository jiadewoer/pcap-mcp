"""Small, bounded actual MCP / frozen v3 validation, with offline replay."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import config, frozen_prose, validation_cases
from .claims import field_registry
from .evidence_io import parse_tool_payload
from .provenance import capture_digest, http_field_evidence
from .reporting import generate_report, render_report
from .research import REQUIRED_UA_PROPERTIES, ResearchAudit, canonical_digest, write_json_atomic
from .validation_agent import MAX_DECISIONS, collect
from .verify import verify_evidence

VERSION = "agent-v3-validation-v1"
REVIEW_LABELS = (
    "source_confusion",
    "unsupported_encoding_or_intent",
    "unsupported_success",
    "counter_or_presence_contradiction",
    "wrong_record",
    "missing_specific_limitations",
    "other",
)


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def fingerprints() -> dict[str, str]:
    root = Path(__file__).resolve().parent
    return {p.name: capture_digest(p) for p in sorted(root.glob("*.py"))}


@contextmanager
def capture_scope(path: Path):
    """Parent verification needs the same explicit authorization as the MCP child."""
    previous = config._SETTINGS
    try:
        config._SETTINGS = replace(
            config.get_settings(), allowed_dirs=(path.parent.resolve(),), redact=True
        )
        yield
    finally:
        config._SETTINGS = previous


def prepare(
    manifest: Path,
    output: Path,
    *,
    models: list[str],
    smoke: bool = True,
    max_requests: int = 8,
    environment: dict[str, Any] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    if (
        not models
        or len(set(models)) != len(models)
        or any(not isinstance(m, str) or not m.strip() for m in models)
        or type(max_requests) is not int
        or not 1 <= max_requests <= 400
        or type(timeout) is not int
        or not 15 <= timeout <= 600
    ):
        raise ValueError("Invalid models, request cap or timeout.")
    origin, cases = validation_cases.load(manifest, smoke=smoke)
    upper_bound = len(cases) * len(models) * (MAX_DECISIONS + len(frozen_prose.ARMS))
    if upper_bound > max_requests:
        raise ValueError(
            f"Plan needs at most {upper_bound} requests; cap is {max_requests}. Nothing prepared."
        )
    if output.exists():
        raise ValueError("Use a new output directory.")
    settings = config.get_settings()
    versions = {}
    for name in ("tshark", "capinfos"):
        completed = subprocess.run(
            [getattr(settings, name), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        versions[name] = completed.stdout.splitlines()[0]
    output.mkdir(parents=True, exist_ok=False)
    (output / "inputs").mkdir()
    (output / "preflight").mkdir()
    frozen = []
    for case in cases:
        relative = "inputs/" + case["id"] + Path(case["path"]).suffix.lower()
        path = output / relative
        shutil.copyfile(case["path"], path)
        if capture_digest(path) != case["capture_sha256"]:
            raise ValueError("Capture changed during copying; preserve partial preparation.")
        row = {k: v for k, v in case.items() if k not in {"path", "capture"}}
        row["capture"] = relative
        try:
            with capture_scope(path):
                payload = http_field_evidence(path)
            oracle = validation_cases.check_oracle(row, payload)
            row["preflight_ok"] = oracle["matched"] is not False and not payload["truncated"]
            write_json_atomic(
                output / "preflight" / (case["id"] + ".json"),
                {
                    "status": "completed",
                    "oracle": oracle,
                    "capture_sha256": payload["capture_sha256"],
                    "field_records_sha256": canonical_digest(payload["field_records"]),
                    "observed_requests": payload["observed_requests"],
                },
            )
        except Exception as exc:
            row["preflight_ok"] = False
            write_json_atomic(
                output / "preflight" / (case["id"] + ".json"),
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
            )
        frozen.append(row)
    rng = random.Random(2037)
    groups = []
    for index, (model, case) in enumerate(((m, c) for m in models for c in frozen), 1):
        arms = list(frozen_prose.ARMS)
        rng.shuffle(arms)
        groups.append(
            {"id": f"group-{index:03d}", "model": model, "case_id": case["id"], "arms": arms}
        )
    protocol = {
        "schema_version": 1,
        "study_version": VERSION,
        "data_origin": origin,
        "models": models,
        "cases": frozen,
        "groups": groups,
        "code_sha256": fingerprints(),
        "max_requests": max_requests,
        "planned_request_upper_bound": upper_bound,
        "max_decisions": MAX_DECISIONS,
        "max_focused_calls": 2,
        "timeout": timeout,
        "transport_retries": 0,
        "format_repairs": 0,
        "temperature": 0,
        "seed": 0,
        "reasoning_effort_requested": "none",
        "reasoning_disabled_verified": False,
        "prompt_sha256": hashlib.sha256(frozen_prose.PROMPT.encode()).hexdigest(),
        "wireshark_versions": versions,
        "environment": environment or {},
        "endpoint_sha256": hashlib.sha256(os.getenv("OPENAI_BASE_URL", "").encode()).hexdigest(),
        "scope": "actual_mcp_then_paired_frozen_v3_not_external_semantic_validation",
    }
    write_json_atomic(output / "protocol.json", protocol)
    (output / "protocol.sha256").write_text(canonical_digest(protocol), encoding="ascii")
    save_summary(output, protocol)
    return protocol


def validate(root: Path) -> dict[str, Any]:
    protocol = read(root / "protocol.json")
    if (
        protocol.get("study_version") != VERSION
        or canonical_digest(protocol) != (root / "protocol.sha256").read_text(encoding="ascii")
        or protocol["code_sha256"] != fingerprints()
    ):
        raise ValueError("Protocol or executable code changed; use the original frozen version.")
    for case in protocol["cases"]:
        path = root / case["capture"]
        if (
            not path.resolve().is_relative_to(root.resolve())
            or capture_digest(path) != case["capture_sha256"]
        ):
            raise ValueError("Frozen capture changed.")
    return protocol


class Budget:
    def __init__(self, limit: int, directory: Path, sanitize: Any):
        self.limit, self.directory, self.sanitize = limit, directory, sanitize
        self.attempts = 0
        directory.mkdir(parents=True, exist_ok=False)

    async def send(self, client: Any, request: dict[str, Any], group: str, phase: str):
        if self.attempts >= self.limit:
            raise ValueError("Hard request budget exhausted.")
        self.attempts += 1
        path = self.directory / f"request-{self.attempts:03d}.json"
        entry: dict[str, Any] = {
            "number": self.attempts,
            "group": group,
            "phase": phase,
            "request_sha256": canonical_digest(request),
            "status": "started",
        }
        write_json_atomic(path, entry)  # Count attempts before network dispatch, even failures.
        adapted = {k: v for k, v in request.items() if k != "reasoning_effort"}
        adapted["extra_body"] = {"reasoning_effort": request["reasoning_effort"]}
        began = time.perf_counter()
        try:
            response = await client.chat.completions.create(**adapted)
            message = response.choices[0].message if response.choices else None
            original = json.dumps(
                message.model_dump(exclude_none=True) if message else {},
                ensure_ascii=False,
                sort_keys=True,
            )
            protected = self.sanitize(original)
            usage: Any = getattr(response, "usage", None)
            entry.update(
                status="completed",
                message_sha256=hashlib.sha256(original.encode()).hexdigest(),
                protected_message=protected[:50_000],
                stored_copy_truncated=len(protected) > 50_000,
                usage=usage.model_dump() if hasattr(usage, "model_dump") else None,
                response_storage="locally_redacted_copy_not_verbatim_original",
            )
            return response
        except Exception as exc:
            entry.update(
                status="failed",
                error_type=type(exc).__name__,
                http_status=getattr(exc, "status_code", None),
            )
            raise
        finally:
            entry["elapsed_seconds"] = round(time.perf_counter() - began, 6)
            write_json_atomic(path, entry)


def shared_result(root: Path, protocol: dict[str, Any], group: dict[str, Any], *, source: bool):
    directory = root / group["id"]
    evidence_path = directory / "evidence.json"
    if not evidence_path.is_file():
        return {
            "field_evidence_available": False,
            "source_verified": False,
            "oracle": {"status": "not_observed", "matched": None},
        }
    evidence = read(evidence_path)
    registry = field_registry(evidence)
    report = generate_report(evidence)
    ua_refs = {ref for ref, row in registry.items() if row["field"] == "http.user_agent"}
    required = {(ref, prop) for ref in ua_refs for prop in REQUIRED_UA_PROPERTIES}
    covered = {(f["record"], f["property"]) for f in report["facts"]} & required
    case = next(c for c in protocol["cases"] if c["id"] == group["case_id"])
    payloads = []
    for item in evidence:
        payload = parse_tool_payload(item["result"])
        if payload and payload.get("schema") == "pcap-mcp.http-fields/v1":
            payloads.append(payload)
    oracles = [validation_cases.check_oracle(case, payload) for payload in payloads]
    oracle = next(
        (o for o in oracles if o["matched"] is True),
        oracles[0] if oracles else {"status": "not_observed", "matched": None},
    )
    verification = (
        read(directory / "source-verification.json")
        if (directory / "source-verification.json").is_file()
        else {}
    )
    if source and payloads:
        with capture_scope(root / case["capture"]):
            verification = verify_evidence(root / case["capture"], evidence)
    return {
        "field_evidence_available": bool(ua_refs),
        "user_agent_occurrences": len(ua_refs),
        "required_predicates": len(required),
        "covered_predicates": len(covered),
        "all_required_predicates_covered": bool(required) and required == covered,
        "source_verified": verification.get("all_records_match") is True,
        "source_matched_records": verification.get("matched_count", 0),
        "oracle": oracle,
    }


def summary(root: Path, protocol: dict[str, Any], *, source: bool = False):
    trials = []
    shared_groups = []
    for group in protocol["groups"]:
        shared = shared_result(root, protocol, group, source=source)
        shared_groups.append({"id": group["id"], **shared})
        evidence_path = root / group["id"] / "evidence.json"
        evidence = read(evidence_path) if evidence_path.is_file() else []
        for arm in group["arms"]:
            directory = root / group["id"] / arm
            status = (
                read(directory / "status.json")
                if (directory / "status.json").is_file()
                else {"status": "unattempted"}
            )
            text_path = directory / "response.txt"
            measured = (
                frozen_prose.metrics(evidence, text_path.read_text(encoding="utf-8"))
                if text_path.is_file()
                else None
            )
            trials.append(
                {
                    "id": group["id"] + "/" + arm,
                    "model": group["model"],
                    "case_id": group["case_id"],
                    "arm": arm,
                    **status,
                    "shared": shared,
                    "prose": measured,
                    "semantic_correctness": "pending_manual_review",
                }
            )
    requests = list((root / "requests").glob("request-*.json"))
    totals = {
        "planned_prose_trials": len(trials),
        "model_request_attempts": len(requests),
        "completed_prose_responses": sum(t["status"] == "completed" for t in trials),
        "structure_and_references_valid": sum(
            bool(t["status"] == "completed" and t["prose"] and t["prose"]["references_valid"])
            for t in trials
        ),
        "nonempty_chinese_prose_with_limitations": sum(
            bool(
                t["status"] == "completed"
                and t["prose"]
                and t["prose"]["references_valid"]
                and not t["prose"]["empty_prose"]
                and t["prose"]["chinese_prose_present"]
                and t["prose"]["nonempty_limitations"]
            )
            for t in trials
        ),
        "program_complete_and_source_verified": sum(
            t["shared"].get("all_required_predicates_covered", False)
            and t["shared"]["source_verified"]
            for t in trials
        ),
        "synthetic_oracle_matched": sum(t["shared"]["oracle"]["matched"] is True for t in trials),
        "semantic_accepted": None,
    }
    return {
        "study_version": VERSION,
        "data_origin": protocol["data_origin"],
        "totals": totals,
        "trials": trials,
        "shared_investigations": {
            "planned": len(shared_groups),
            "program_complete_and_source_verified": sum(
                row.get("all_required_predicates_covered", False) and row["source_verified"]
                for row in shared_groups
            ),
            "synthetic_oracle_matched": sum(
                row["oracle"]["matched"] is True for row in shared_groups
            ),
            "groups": shared_groups,
        },
        "scope": protocol["scope"],
        "semantic_correctness": "not_automatically_scored",
        "condition_comparison": compare_conditions(trials, protocol["models"]),
    }


def compare_conditions(trials: list[dict[str, Any]], models: list[str]):
    """Descriptive paired counts; do not turn a small smoke run into a significance claim."""

    def gate(row):
        return bool(
            row["status"] == "completed" and row["prose"] and row["prose"]["references_valid"]
        )

    conditions = []
    pairs = []
    for model in models:
        selected = [t for t in trials if t["model"] == model]
        for arm in frozen_prose.ARMS:
            rows = [t for t in selected if t["arm"] == arm]
            conditions.append(
                {
                    "model": model,
                    "arm": arm,
                    "planned": len(rows),
                    "completed": sum(t["status"] == "completed" for t in rows),
                    "structure_and_references_valid": sum(gate(t) for t in rows),
                    "semantic_accepted": None,
                }
            )
        counts = {
            "both_valid": 0,
            "json_only_valid": 0,
            "schema_only_valid": 0,
            "neither_valid_or_missing": 0,
        }
        for case in sorted({t["case_id"] for t in selected}):
            by_arm = {t["arm"]: t for t in selected if t["case_id"] == case}
            first, second = (gate(by_arm[arm]) for arm in frozen_prose.ARMS)
            label = (
                "both_valid"
                if first and second
                else "json_only_valid"
                if first
                else "schema_only_valid"
                if second
                else "neither_valid_or_missing"
            )
            counts[label] += 1
        pairs.append({"model": model, "planned_pairs": sum(counts.values()), **counts})
    return {
        "by_model_and_arm": conditions,
        "paired_counts": pairs,
        "scope": "descriptive_structure_and_reference_comparison_not_semantics_or_significance",
    }


def save_summary(root: Path, protocol: dict[str, Any]):
    result = summary(root, protocol)
    write_json_atomic(root / "summary.json", result)
    lines = [
        "# v3 实际 MCP 小批验收",
        "",
        "模型正文的语义需要人工复核。程序事实和来源重提取单列。",
        "",
        "```json",
        json.dumps(result["totals"], ensure_ascii=False, indent=2),
        "```",
        "",
        "未尝试、工具失败、模型错误均保留在计划分母；两个正文条件共享同一调查证据。",
        "",
        "新合成模板不代表外部真实流量。reasoning_effort=none 是请求参数，不能证明后端已关闭推理。",
        "",
    ]
    for trial in result["trials"]:
        lines.append("- " + trial["id"] + ": " + trial["status"])
    (root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


async def run(root: Path, client: Any, *, sanitize=lambda text: text, session_factory=None):
    protocol = validate(root)
    marker = root / "run-started.json"
    with marker.open("x", encoding="utf-8") as handle:
        json.dump({"status": "started", "no_resume": True}, handle)
    budget = Budget(protocol["max_requests"], root / "requests", sanitize)
    if session_factory is None:
        from contextlib import asynccontextmanager

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        @asynccontextmanager
        async def session_factory(capture):
            env = dict(os.environ)
            env.update(PCAP_MCP_ALLOWED_DIRS=str(capture.parent.resolve()), PCAP_MCP_REDACT="on")
            parameters = StdioServerParameters(
                command=sys.executable, args=["-m", "pcap_mcp.server"], env=env
            )
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    yield session

    try:
        for group in protocol["groups"]:
            directory = root / group["id"]
            directory.mkdir()
            case = next(c for c in protocol["cases"] if c["id"] == group["case_id"])
            path = root / case["capture"]
            failure = None
            audit = ResearchAudit(
                directory / "evidence.json", directory / "decision-audit.json", sanitize=sanitize
            )
            print(
                f"{group['id']} {case['id']}: start; global cap {protocol['max_requests']}",
                flush=True,
            )
            if not case["preflight_ok"]:
                failure = "preflight_failed"
            else:
                try:
                    async with session_factory(path) as session:
                        tools = (await session.list_tools()).tools

                        async def send(request, phase, group_id=group["id"]):
                            return await budget.send(client, request, group_id, phase)

                        evidence = await collect(
                            session,
                            tools,
                            str(path.resolve()),
                            case["goal"],
                            group["model"],
                            send,
                            audit,
                        )
                    audit.finish("completed")
                    if capture_digest(path) != case["capture_sha256"]:
                        raise ValueError("Capture changed during investigation.")
                    with capture_scope(path):
                        verified = verify_evidence(path, evidence)
                    write_json_atomic(directory / "source-verification.json", verified)
                    closed = generate_report(evidence)
                    write_json_atomic(directory / "program-facts.json", closed)
                    (directory / "program-facts.md").write_text(
                        render_report(closed), encoding="utf-8"
                    )
                    if not any(
                        r["field"] == "http.user_agent" for r in field_registry(evidence).values()
                    ):
                        failure = "no_user_agent_field_evidence"
                except Exception as exc:
                    failure = "investigation_failed"
                    audit.finish("failed", type(exc).__name__)
            for arm in group["arms"]:
                arm_dir = directory / arm
                arm_dir.mkdir()
                if failure:
                    write_json_atomic(arm_dir / "status.json", {"status": failure})
                    continue
                evidence = read(directory / "evidence.json")
                request = frozen_prose.request(group["model"], case["goal"], evidence, arm)
                write_json_atomic(arm_dir / "request.json", request)
                write_json_atomic(arm_dir / "status.json", {"status": "started"})
                try:
                    response = await budget.send(client, request, group["id"], arm)
                    message = response.choices[0].message if response.choices else None
                    text = (message.content or "") if message else ""
                    protected = sanitize(text)
                    oversized = len(text) > 50_000 or len(protected) > 50_000
                    protected = protected[:50_000]
                    (arm_dir / "response.txt").write_text(protected, encoding="utf-8")
                    write_json_atomic(
                        arm_dir / "response-metadata.json",
                        {
                            "original_sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "original_characters": len(text),
                            "protected_copy_changed": protected != text,
                            "unexpected_tool_calls": bool(message and message.tool_calls),
                            "stored_copy_truncated": oversized,
                        },
                    )
                    report = generate_report(evidence, protected)
                    write_json_atomic(arm_dir / "program-report.json", report)
                    (arm_dir / "program-report.md").write_text(
                        render_report(report), encoding="utf-8"
                    )
                    status = (
                        "invalid_response"
                        if not message or message.tool_calls or oversized
                        else "completed"
                    )
                    write_json_atomic(arm_dir / "status.json", {"status": status})
                except Exception as exc:
                    write_json_atomic(
                        arm_dir / "status.json",
                        {"status": "request_failed", "error_type": type(exc).__name__},
                    )
                print(
                    f"{group['id']} {arm}: {read(arm_dir / 'status.json')['status']}; "
                    f"requests {budget.attempts}/{budget.limit}",
                    flush=True,
                )
                save_summary(root, protocol)
    finally:
        result = save_summary(root, protocol)
        write_json_atomic(marker, {"status": "finished_or_interrupted", "no_resume": True})
        review_template(root, result)
        hashes = {
            p.relative_to(root).as_posix(): capture_digest(p)
            for p in root.rglob("*")
            if p.is_file()
            and p.name
            not in {"artifact-sha256.json", "review-template.json", "report.md", "summary.json"}
        }
        write_json_atomic(root / "artifact-sha256.json", hashes)
    return result


def review_template(root: Path, result: dict[str, Any]):
    write_json_atomic(
        root / "review-template.json",
        {
            "schema_version": 1,
            "allowed_labels": REVIEW_LABELS,
            "instruction": "逐条对照 program-facts 与模型正文。"
            "approved 仅表示这次正文人工验收；pending 不计成功。",
            "trials": [
                {
                    "id": t["id"],
                    "response_sha256": capture_digest(root / t["id"] / "response.txt")
                    if (root / t["id"] / "response.txt").is_file()
                    else None,
                    "decision": "pending",
                    "labels": [],
                    "note": "",
                    "reviewer": "",
                }
                for t in result["trials"]
            ],
        },
    )


def replay(root: Path, *, source: bool = False):
    protocol = validate(root)
    inventory = root / "artifact-sha256.json"
    if inventory.is_file():
        for relative, digest in read(inventory).items():
            path = root / relative
            if not path.resolve().is_relative_to(root.resolve()) or capture_digest(path) != digest:
                raise ValueError("Saved artifact changed: " + relative)
    result = summary(root, protocol, source=source)
    if result != read(root / "summary.json"):
        raise ValueError("Saved summary does not reproduce.")
    return result


def review(root: Path, review_path: Path):
    result = replay(root)
    expected = {t["id"] for t in result["trials"]}
    rows = read(review_path)["trials"]
    if len(rows) != len(expected) or {r["id"] for r in rows} != expected:
        raise ValueError("Review must cover every planned trial exactly once.")
    for row in rows:
        text = root / row["id"] / "response.txt"
        actual_digest = capture_digest(text) if text.is_file() else None
        if row["response_sha256"] != actual_digest:
            raise ValueError("Review is for a different response.")
        if (
            row["decision"] not in {"pending", "approved", "rejected"}
            or not isinstance(row["labels"], list)
            or set(row["labels"]) - set(REVIEW_LABELS)
        ):
            raise ValueError("Invalid review decision or labels.")
        if row["decision"] == "approved" and (row["labels"] or not actual_digest):
            raise ValueError("Cannot approve missing response or a response with error labels.")
        reviewer = row.get("reviewer", "")
        if not isinstance(reviewer, str) or (row["decision"] != "pending" and not reviewer.strip()):
            raise ValueError("Reviewed entries require a reviewer.")
    return {
        "planned": len(rows),
        **{
            key: sum(r["decision"] == key for r in rows)
            for key in ("pending", "approved", "rejected")
        },
        "scope": "human_review_of_saved_prose_not_general_model_accuracy",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", type=Path)
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--run", type=Path)
    action.add_argument("--replay", type=Path)
    action.add_argument("--review", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--model", action="append")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--max-requests", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--environment-json", type=Path)
    parser.add_argument("--verify-source", action="store_true")
    parser.add_argument("--review-json", type=Path)
    args = parser.parse_args()
    try:
        if args.generate:
            print(validation_cases.generate(args.generate))
        elif args.prepare:
            if not args.manifest or not args.output:
                raise ValueError("Prepare requires manifest and new output.")
            protocol = prepare(
                args.manifest,
                args.output,
                models=args.model or ["qwen3:8b"],
                smoke=not args.full,
                max_requests=args.max_requests,
                timeout=args.timeout,
                environment=read(args.environment_json) if args.environment_json else None,
            )
            print(
                f"Prepared {len(protocol['cases'])} cases; "
                f"at most {protocol['planned_request_upper_bound']} requests; no model calls."
            )
        elif args.replay:
            result = replay(args.replay, source=args.verify_source)
            if args.output:
                if args.output.exists():
                    raise ValueError("Replay output already exists.")
                write_json_atomic(args.output, result)
            print("Saved summary reproduces; no model calls.")
        elif args.review:
            if not args.review_json:
                raise ValueError("Review requires --review-json.")
            print(json.dumps(review(args.review, args.review_json), ensure_ascii=False))
        else:
            from openai import AsyncOpenAI

            from .security import redact

            protocol = validate(args.run)
            key, url = os.getenv("OPENAI_API_KEY", ""), os.getenv("OPENAI_BASE_URL", "")
            if (
                not key
                or not url
                or hashlib.sha256(url.encode()).hexdigest() != protocol["endpoint_sha256"]
            ):
                raise ValueError("API key missing or endpoint changed.")

            def sanitize(text):
                return redact(text.replace(key, "[redacted]").replace(url, "[redacted]"))

            async def live():
                async with AsyncOpenAI(
                    api_key=key, base_url=url, max_retries=0, timeout=protocol["timeout"]
                ) as client:
                    return await run(args.run, client, sanitize=sanitize)

            asyncio.run(live())
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        parser.exit(
            2,
            f"validation stopped: {detail}. Preserve output; do not rerun a started plan.\n",
        )


if __name__ == "__main__":
    main()
