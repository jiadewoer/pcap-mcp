"""One request per replay condition; fixed proposal reused for every offline gate."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .lineage import (
    analyze_saved,
    build_suite,
    deterministic_baseline,
    evaluate_proposal,
    model_messages,
    parse_proposal,
    plan_runs,
    render_study_report,
    summarize,
    validate_suite,
)
from .research import canonical_digest, write_json_atomic


async def run_study(
    client: Any, model: str, suite: dict[str, Any], output: Path, *,
    repeats: int = 1, order_seed: int = 2026, seed: int = 0,
    json_mode: bool = True, sanitize: Callable[[str], str] = lambda text: text,
    declarations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_suite(suite)
    planned = plan_runs(suite, repeats, order_seed)
    if not 0 <= seed <= 2**31 - 1:
        raise ValueError("Invalid model seed.")
    output.mkdir(parents=True, exist_ok=False)
    protocol = {
        "schema_version": 1, "project_version": __version__, "model": model,
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "repeats": repeats,
        "suite_sha256": canonical_digest(suite), "planned": planned,
        "temperature": 0.0, "model_seed": seed, "order_seed": order_seed,
        "logical_requests_per_run": 1, "format_repairs": 0,
        "transport_retries_cli": 0, "json_mode": json_mode,
        "gate_comparison": "same_parsed_proposal_no_model_regeneration",
        "declared_environment": declarations or {},
    }
    write_json_atomic(output / "suite.json", suite)
    write_json_atomic(output / "protocol.json", protocol)
    cases = {case["id"]: case for case in suite["cases"]}
    write_json_atomic(output / "deterministic-baseline.json", deterministic_baseline(suite))
    runs = []
    write_json_atomic(output / "summary.json", summarize(suite, planned, runs))
    for item in planned:
        folder = output / item["run_id"]
        folder.mkdir()
        case = cases[item["case_id"]]
        messages = model_messages(case, item["view"])
        write_json_atomic(folder / "request.json", {
            "model": model, "messages": messages, "temperature": 0.0, "seed": seed,
            "response_format": {"type": "json_object"} if json_mode else None,
        })
        trial = {**item, "status": "started", "request_sha256": canonical_digest(messages)}
        write_json_atomic(folder / "trial.json", trial)
        started = time.monotonic()
        try:
            args = {
                "model": model, "messages": messages, "temperature": 0.0, "seed": seed,
            }
            if json_mode:
                args["response_format"] = {"type": "json_object"}
            response = await client.chat.completions.create(**args)
            content = response.choices[0].message.content if response.choices else ""
            content = content or ""
            protected = sanitize(content)
            usage = getattr(response, "usage", None)
            write_json_atomic(folder / "response.json", {
                "original_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "original_characters": len(content), "text": protected[:50_000],
                "stored_copy_truncated": len(protected) > 50_000,
                "stored_copy_changed": protected != content,
                "usage": usage.model_dump() if hasattr(usage, "model_dump") else None,
            })
            proposal = parse_proposal(content)
            trial["evaluation"] = evaluate_proposal(proposal, case)
            stored = sanitize(json.dumps(proposal, ensure_ascii=False, indent=2))
            (folder / "proposal.json").write_text(stored, encoding="utf-8")
            trial["proposal_changed_by_storage_redaction"] = (
                stored != json.dumps(proposal, ensure_ascii=False, indent=2)
            )
            trial["status"] = "completed"
            trial["format_valid"] = True
        except Exception as exc:
            trial["status"] = "failed"
            trial["error_type"] = type(exc).__name__
            trial["format_valid"] = False if isinstance(exc, ValueError) else None
            # No arbitrary provider exception text: it can contain URLs or credentials.
        trial["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json_atomic(folder / "trial.json", trial)
        runs.append(trial)
        summary = summarize(suite, planned, runs)
        write_json_atomic(output / "summary.json", summary)
        (output / "report.md").write_text(render_study_report(summary), encoding="utf-8")
        print(f"{item['run_id']} {item['view']}: {trial['status']}", flush=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-dir", type=Path, default=Path("benchmarks/lineage"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--analyze", type=Path, help="Existing frozen study; no model calls")
    parser.add_argument("--analysis-output", type=Path)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--order-seed", type=int, default=2026)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--request-timeout", type=int, default=120)
    parser.add_argument("--response-format", choices=("json", "prompt"), default="json")
    args = parser.parse_args()
    try:
        if args.analyze:
            if args.output_dir or args.build_only or not args.analysis_output:
                raise ValueError("Analyze requires only an existing study and new analysis output.")
            result = analyze_saved(args.analyze.resolve(), args.analysis_output.resolve())
            print(f"Replayed {result['attempted']} saved trials without model calls.")
            return
        if not args.output_dir or args.analysis_output:
            raise ValueError("Supply a new output directory.")
        suite = build_suite(args.seed_dir.resolve())
        if args.build_only:
            plan_runs(suite, args.repeats, args.order_seed)
            args.output_dir.mkdir(parents=True, exist_ok=False)
            write_json_atomic(args.output_dir / "suite.json", suite)
            write_json_atomic(
                args.output_dir / "deterministic-baseline.json", deterministic_baseline(suite)
            )
            print(f"Validated {len(suite['pairs'])} pairs, {len(suite['cases'])} cases.")
            return
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        base_url = os.getenv("OPENAI_BASE_URL", "").strip()
        model = os.getenv("OPENAI_MODEL", "").strip()
        if not all((api_key, base_url, model)) or not 15 <= args.request_timeout <= 600:
            raise ValueError("Set model environment and a timeout between 15 and 600 seconds.")
        # Optional dependencies are imported only when actual API use is requested.
        from openai import AsyncOpenAI

        from .security import redact

        def local_copy(text: str) -> str:
            return redact(text.replace(api_key, "[redacted]").replace(base_url, "[endpoint]"))

        declarations = {
            "model_digest": os.getenv("PCAP_MCP_MODEL_DIGEST"),
            "ollama_version": os.getenv("PCAP_MCP_OLLAMA_VERSION"),
            "endpoint_sha256": hashlib.sha256(base_url.encode("utf-8")).hexdigest(),
            "python": platform.python_version(),
            "request_timeout_s": args.request_timeout,
            "platform": {"system": platform.system(), "machine": platform.machine()},
            "seed_is_not_a_cross_backend_determinism_guarantee": True,
        }

        async def launch() -> None:
            async with AsyncOpenAI(
                api_key=api_key, base_url=base_url, timeout=args.request_timeout, max_retries=0
            ) as client:
                await run_study(
                    client, model, suite, args.output_dir.resolve(), repeats=args.repeats,
                    order_seed=args.order_seed, seed=args.seed,
                    json_mode=args.response_format == "json", sanitize=local_copy,
                    declarations=declarations,
                )

        asyncio.run(launch())
    except (OSError, ValueError, ImportError) as exc:
        parser.exit(2, f"lineage-study: {exc}\n")


if __name__ == "__main__":
    main()
