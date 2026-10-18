"""Reproducibility, leakage, failure-denominator and wire-request tests."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from openai import AsyncOpenAI

from pcap_mcp import lineage
from pcap_mcp import reporting_study as study
from pcap_mcp.research import write_json_atomic

ROOT = Path(__file__).resolve().parents[1]


class FakeModel:
    """Protocol fixture, not an experiment with model-generated answers."""

    def __init__(self, suite, fail_every=0):
        self.suite, self.fail_every, self.calls = suite, fail_every, 0
        self.chat = SimpleNamespace(completions=self)

    async def create(self, **body):
        self.calls += 1
        if self.fail_every and self.calls % self.fail_every == 0:
            raise RuntimeError("private-key http://secret.example/v1/ should never be stored")
        case = next(
            case
            for case in self.suite["cases"]
            if any(
                body["messages"][1]["content"] == study.prompt(case, view, "original")[1]["content"]
                for view in ("structured", "flat")
            )
        )
        if "controller generates field facts" in body["messages"][0]["content"]:
            text = '{"schema_version":1,"hypotheses":[],"limitations":[]}'
        else:
            # A deliberately deterministic SDK fixture, used only to test replay integrity.
            from pcap_mcp.reporting import as_proposal, generate_report

            text = json.dumps(as_proposal(generate_report(lineage.evidence_for(case))))
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=text), finish_reason="stop")],
            model="fixture",
            usage=None,
        )


def test_offline_gold_check_and_new_family_split():
    result = study.check(ROOT)
    assert result["no_model_calls"]
    assert result["program_baselines"]["development"]["exact_cases"] == 10
    assert result["program_baselines"]["heldout"]["exact_cases"] == 12
    loaded = study.suites(ROOT)
    assert {case["pair"] for case in loaded["development"]["cases"]}.isdisjoint(
        {case["family"] for case in loaded["heldout"]["cases"]}
    )


def test_original_prompt_exactly_matches_frozen_native_contract_and_gold_never_leaks():
    case = study.suites(ROOT)["development"]["cases"][0]
    for view in ("structured", "flat"):
        original = study.prompt(case, view, "original")
        assert original[0]["content"] == lineage.PROMPT + study.NATIVE_TYPES
        assert original[1] == lineage.model_messages(case, view)[1]
        for arm in study.ARMS:
            messages = study.prompt(case, view, arm)
            assert messages[1] == original[1]
            assert '"gold"' not in messages[1]["content"]
            assert '"slots"' not in messages[1]["content"]


def test_balanced_multi_model_schedule_and_no_calls_during_freeze(tmp_path):
    protocol = study.freeze(
        ROOT, tmp_path / "dev", phase="development", models=["a", "b"], repeats=2
    )
    assert len(protocol["planned"]) == 320
    suite = study.read_json(tmp_path / "dev/suite.json")
    assert protocol["planned"] == study.schedule(protocol, suite)
    for model in ("a", "b"):
        for arm in study.ARMS:
            assert (
                sum(row["model"] == model and row["method"] == arm for row in protocol["planned"])
                == 40
            )
    assert study.replay(tmp_path / "dev")["totals"][0]["facts"]["covered"] == 0


def test_live_fixture_and_fixed_output_replay_match_with_failures_retained(tmp_path):
    root = tmp_path / "dev"
    protocol = study.freeze(ROOT, root, phase="development", models=["fixture"])
    model = FakeModel(study.read_json(root / "suite.json"), fail_every=9)
    original = asyncio.run(study.run(root, model))
    replayed = study.replay(root, root / "replayed-summary.json")
    assert original == replayed
    assert model.calls == len(protocol["planned"]) == 80
    assert sum(row["status"] == "failed" for row in original["trials"]) == 8
    assert all(row["planned"] == 10 for row in original["totals"])
    assert "private-key" not in (root / "summary.json").read_text()
    assert "secret.example" not in (root / "summary.json").read_text()
    assert (root / "summary.json").read_bytes() == (root / "replayed-summary.json").read_bytes()
    with pytest.raises(ValueError, match="already attempted"):
        asyncio.run(study.run(root, model))


def test_holdout_requires_development_selection_and_program_keeps_closed_facts_on_api_failure(
    tmp_path,
):
    with pytest.raises(ValueError, match="selection"):
        study.freeze(ROOT, tmp_path / "bad", phase="heldout", models=["fixture"])
    dev = tmp_path / "dev"
    study.freeze(ROOT, dev, phase="development", models=["fixture"])
    model = FakeModel(study.read_json(dev / "suite.json"))
    asyncio.run(study.run(dev, model))
    selected = study.select(dev)
    assert selected["arm"] == "original"  # tie policy is fixed before results
    heldout = tmp_path / "heldout"
    protocol = study.freeze(ROOT, heldout, phase="heldout", models=["fixture"], selected=selected)
    model = FakeModel(study.read_json(heldout / "suite.json"), fail_every=1)
    result = asyncio.run(study.run(heldout, model))
    assert len(protocol["planned"]) == model.calls == 72
    assert result == study.replay(heldout)
    program = [row for row in result["totals"] if row["method"] == "program"]
    assert all(row["completed"] == 0 and row["failed"] == 12 for row in program)
    assert all(row["facts"]["covered"] == row["facts"]["required_all_planned"] for row in program)
    assert all(row["exact_with_valid_prose_or_proposal"] == 0 for row in program)
    with pytest.raises(ValueError, match="development"):
        study.select(heldout)


@pytest.mark.parametrize(
    "target", ["suite", "request", "response", "proposal", "trial-evaluation", "trial-status"]
)
def test_frozen_output_tampering_is_rejected(tmp_path, target):
    root = tmp_path / "dev"
    study.freeze(ROOT, root, phase="development", models=["fixture"])
    asyncio.run(study.run(root, FakeModel(study.read_json(root / "suite.json"))))
    folder = root / "run-0001"
    if target == "suite":
        path = root / "suite.json"
        value = study.read_json(path)
        value["scope"] = "tampered"
    elif target == "request":
        path = folder / "request.json"
        value = study.read_json(path)
        value["messages"][0]["content"] += "changed"
    elif target == "response":
        path = folder / "response.json"
        value = study.read_json(path)
        value["text"] += " "
    elif target == "proposal":
        path = folder / "proposal.json"
        value = study.read_json(path)
        value["facts"][0]["value"] = "changed"
    elif target == "trial-status":
        path = folder / "trial.json"
        value = study.read_json(path)
        value.update(status="failed", failure_label="api_error")
    else:
        path = folder / "trial.json"
        value = study.read_json(path)
        value["evaluation"]["gates"]["off"]["facts"]["covered"] = 0
    write_json_atomic(path, value)
    with pytest.raises(ValueError):
        study.replay(root)


def test_actual_sdk_wire_matches_saved_body(tmp_path):
    seen = []

    def respond(request):
        seen.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "fixture",
                "object": "chat.completion",
                "created": 0,
                "model": "fixture",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "{}"},
                    }
                ],
            },
        )

    case = study.suites(ROOT)["development"]["cases"][0]
    protocol = study.freeze(ROOT, tmp_path / "dev", phase="development", models=["fixture"])
    body = study.request_for(protocol, case, {"model": "fixture", "view": "flat", "method": "both"})

    async def execute():
        async with AsyncOpenAI(
            api_key="fixture",
            base_url="http://fixture/v1/",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
        ) as client:
            await study.sdk_call(client, body)

    asyncio.run(execute())
    assert seen == [body]
    assert "extra_body" not in seen[0]


def test_old_checker_files_remain_byte_identical():
    expected = {
        "claims.py": "1f2d4ae483e68cd470f880bdd7449825364c76bb187562523f430f30fb2b3a31",
        "lineage.py": "fabe735e6d9b15cb3fadda74c68c01dc5d6c9a2190416c274dd46021f11c4371",
        "research.py": "46b502a0b70a46df212a4dd34b049737b7bdb65309fe87a4cefb31f344516e09",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((ROOT / "src/pcap_mcp" / name).read_bytes()).hexdigest() == digest
