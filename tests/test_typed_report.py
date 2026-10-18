"""Actual Agent finalization path, including rejection and budget behavior."""

import asyncio
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_agent import TOOLS, FakeMessage, FakeSession, call

from pcap_mcp import agent
from pcap_mcp import typed_report as typed
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.research import ResearchAudit

INPUT = Path(__file__).resolve().parents[1] / "agent-v2/input"


def evidence(number=2):
    return json.loads((INPUT / f"{number:02d}.json").read_text(encoding="utf-8-sig"))


def answer(case):
    records = {r["reference"]: r["facts"] for r in case["packet"]["records"]}
    return {
        "schema_version": 2,
        "case_id": case["case_id"],
        "claims": [
            {
                **row,
                "state": "known" if row["property"] in records[row["reference"]] else "unknown",
                "value": records[row["reference"]].get(row["property"]),
            }
            for row in case["task"]["required"]
        ],
        "interpretations": [],
    }


def change_record(source, change):
    result = deepcopy(source)
    payload = parse_tool_payload(result[1]["result"])
    change(payload)
    result[1]["result"] = (
        '<untrusted_pcap_data note="fixture">\n' + json.dumps(payload) + "\n</untrusted_pcap_data>"
    )
    return result


class Client:
    def __init__(self, decisions=(), change=None, finish="stop"):
        self.decisions = list(decisions)
        self.requests = []
        self.change = change
        self.finish = finish
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self, **request):
        self.requests.append(deepcopy(request))
        if "tools" in request:
            message = self.decisions.pop(0)
        else:
            case = json.loads(request["messages"][1]["content"])
            body = answer(case)
            if self.change:
                self.change(body)
            message = FakeMessage(json.dumps(body, ensure_ascii=False))
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message, finish_reason=self.finish)]
        )


@pytest.mark.parametrize("number,total", [(1, 12), (2, 6), (3, 6), (4, 12)])
def test_all_real_saved_cases_use_core_contract(number, total):
    case = typed.context(evidence(number))
    body = answer(case)
    result = typed.check(case, body)
    assert result["all_required_values_match"]
    assert result["required_values"] == total
    assert result["automatic_acceptance"] is False
    assert "source_role" not in json.dumps(typed.schema(case))


@pytest.mark.parametrize(
    "prop,value",
    [
        ("present", False),
        ("present", 1),
        ("display_value", None),
        ("transformations.unicode_controls_removed", False),
        ("transformations.unicode_controls_removed", 0.0),
        ("transformations.unicode_controls_removed", 1),
    ],
)
def test_strict_presence_empty_and_count_types(prop, value):
    case = typed.context(evidence())
    body = answer(case)
    next(r for r in body["claims"] if r["property"] == prop)["value"] = value
    checked = typed.check(case, body)
    assert not checked["all_required_values_match"]
    assert "| 字段引用 |" not in typed.render(case, checked)


def test_unknown_is_not_zero_and_invalid_type_is_not_known():
    def change(p):
        row = p["field_records"][-1]
        del row["transformations"]["unicode_controls_removed"]
        row["input_decoding"]["tshark_display_replacement_characters"] = False

    case = typed.context(change_record(evidence(), change))
    body = answer(case)
    unknown = [r for r in body["claims"] if r["state"] == "unknown"]
    assert len(unknown) == 2 and all(r["value"] is None for r in unknown)
    assert typed.check(case, body)["all_required_values_match"]
    unknown[0].update(state="known", value=0)
    assert not typed.check(case, body)["all_required_values_match"]


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b["claims"].pop(),
        lambda b: b["claims"].append(deepcopy(b["claims"][0])),
        lambda b: b.update(claims=[]),
        lambda b: b["claims"].__setitem__(1, deepcopy(b["claims"][0])),
    ],
)
def test_missing_duplicates_and_empty_are_not_success(change):
    case = typed.context(evidence())
    body = answer(case)
    change(body)
    assert not typed.check(case, body)["all_required_values_match"]


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.update(schema_version=True),
        lambda b: b.update(schema_version=1),
        lambda b: b.update(case_id="other"),
        lambda b: b["claims"][0].update(source_role=None),
        lambda b: b["claims"][0].update(reference="E99/F4:http.user_agent/0"),
        lambda b: b.update(interpretations=[{"text": "x", "basis": ["E99/F4:http.user_agent/0"]}]),
    ],
)
def test_schema_or_binding_errors_rejected(change):
    case = typed.context(evidence())
    body = answer(case)
    change(body)
    with pytest.raises(ValueError):
        typed.check(case, body)


@pytest.mark.parametrize("text", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', "```json\n{}\n```"])
def test_strict_json_no_repairs(text):
    with pytest.raises(ValueError):
        typed.decode(text)


def test_case_binding_changes_with_record_values():
    a = typed.context(evidence())
    b = typed.context(
        change_record(evidence(), lambda p: p["field_records"][-1].update(display_value="changed"))
    )
    assert a["case_id"] != b["case_id"]
    with pytest.raises(ValueError):
        typed.check(b, answer(a))


@pytest.mark.parametrize("kind", ["truncated", "error", "payload_truncated"])
def test_unusable_evidence_excluded(kind):
    data = evidence()
    if kind == "payload_truncated":
        data = change_record(data, lambda p: p.update(truncated=True))
    else:
        data[1][kind] = True
    with pytest.raises(ValueError):
        typed.context(data)


def test_injected_table_text_and_model_prose_are_never_published():
    text = "`|\n# heading<script>boom</script>"
    case = typed.context(
        change_record(evidence(), lambda p: p["field_records"][-1].update(display_value=text))
    )
    body = answer(case)
    body["interpretations"] = [
        {"text": "UNVERIFIED ATTACK SUCCESS", "basis": [body["claims"][0]["reference"]]}
    ]
    checked = typed.check(case, body)
    rendered = typed.render(case, checked)
    assert text not in rendered and "<script>" not in rendered
    assert "UNVERIFIED ATTACK SUCCESS" not in rendered
    assert checked["interpretations"] == body["interpretations"]


def test_live_agent_tool_decision_reaches_same_typed_finalizer(tmp_path):
    data = evidence()
    client = Client(
        [FakeMessage(tool_calls=[call("http", "inspect_http_requests", {"path": "elsewhere"})])]
    )
    session = FakeSession({row["tool"]: row["result"] for row in data})
    audit = ResearchAudit(tmp_path / "evidence.json", tmp_path / "audit.json")
    result = asyncio.run(
        agent.investigate(
            client,
            session,
            "fake",
            "bound.pcap",
            "检查HTTP",
            TOOLS,
            report_format="typed",
            max_calls=1,
            max_rounds=2,
            audit=audit,
        )
    )
    assert len(client.requests) == 2 and result.model_rounds == 2
    assert session.calls[-1][1] == {"path": "bound.pcap", "evidence_mode": "field"}
    assert result.claim_checks["all_required_values_match"]
    assert client.requests[-1]["response_format"]["type"] == "json_schema"
    assert audit.data["responses"][-1]["phase"] == "typed_final"
    assert audit.data["typed_check"] == result.claim_checks


def test_early_stop_does_not_publish_decision_narrative():
    data = evidence()
    client = Client(
        [
            FakeMessage(tool_calls=[call("http", "inspect_http_requests", {})]),
            FakeMessage("MODEL DECISION NARRATIVE"),
        ]
    )
    result = asyncio.run(
        agent.investigate(
            client,
            FakeSession({r["tool"]: r["result"] for r in data}),
            "fake",
            "bound.pcap",
            "检查HTTP",
            TOOLS,
            report_format="typed",
            max_calls=3,
            max_rounds=4,
        )
    )
    assert len(client.requests) == 3
    assert "MODEL DECISION NARRATIVE" not in result.markdown()


def test_mismatched_facts_not_repaired_or_published(tmp_path):
    client = Client(change=lambda b: b["claims"][0].update(value=False))
    result = asyncio.run(
        agent.report_from_evidence(
            client,
            "fake",
            [agent.Evidence(**r) for r in evidence()],
            capture="saved.pcap",
            goal="检查HTTP",
            audit=ResearchAudit(tmp_path / "ev.json", tmp_path / "audit.json"),
        )
    )
    assert len(client.requests) == 1
    assert not result.claim_checks["all_required_values_match"]
    assert "| 字段引用 |" not in result.report
    assert (tmp_path / "ev.json").exists()


@pytest.mark.parametrize("finish", ["length", None])
def test_truncated_model_output_not_published_or_retried(finish, tmp_path):
    client = Client(finish=finish)
    audit = ResearchAudit(tmp_path / "ev.json", tmp_path / "audit.json")
    with pytest.raises(agent.AgentError):
        asyncio.run(
            agent.report_from_evidence(
                client,
                "fake",
                [agent.Evidence(**r) for r in evidence()],
                capture="saved.pcap",
                goal="检查HTTP",
                audit=audit,
            )
        )
    assert len(client.requests) == 1 and len(audit.data["responses"]) == 1
    assert not audit.data["responses"][0]["format_valid"]


def test_no_budget_or_no_fields_stops_before_model():
    client = Client()
    with pytest.raises(agent.AgentError):
        asyncio.run(agent.report_from_evidence(client, "fake", [], capture="x", goal="x"))
    with pytest.raises(agent.AgentError):
        asyncio.run(
            agent.report_from_evidence(
                client,
                "fake",
                [agent.Evidence(**r) for r in evidence()],
                capture="x",
                goal="x",
                rounds=2,
                max_rounds=2,
            )
        )
    assert client.requests == []
