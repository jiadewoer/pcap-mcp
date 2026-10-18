"""Program reports remain available when model text contains invalid/false claims."""

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

import pytest
from test_agent import TOOLS, FakeClient, FakeMessage, FakeSession, call

from pcap_mcp import agent, reporting
from pcap_mcp.research import ResearchAudit

INPUT = Path(__file__).resolve().parents[1] / "agent-v2/input"


def saved(number=4):
    return json.loads((INPUT / f"{number:02d}.json").read_text(encoding="utf-8-sig"))


@pytest.mark.parametrize(
    "text", ["not JSON", '{"property":"tsh3ark","value":null}', "ATTACK SUCCEEDED", ""]
)
def test_guarded_fields_never_depend_on_model_text(text):
    evidence = saved()
    result = agent._finish(
        "检查HTTP", "case.pcap", text, [agent.Evidence(**r) for r in evidence], 1, "guarded"
    )
    expected = reporting.generate_report(evidence)
    assert result.program_report["facts"] == expected["facts"]
    assert result.program_report["attributions"] == expected["attributions"]
    assert result.program_report["automatic_acceptance"] is False
    assert "ATTACK SUCCEEDED" not in result.markdown() and "tsh3ark" not in result.markdown()
    assert result.program_report["model_prose"]["hypotheses"] == []


def test_one_model_tool_decision_then_real_controller_report_no_second_request(tmp_path):
    rows = saved()
    client = FakeClient(
        FakeMessage(tool_calls=[call("http", "inspect_http_requests", {})])
    )
    session = FakeSession({row["tool"]: row["result"] for row in rows})
    audit = ResearchAudit(tmp_path / "evidence.json", tmp_path / "audit.json")
    result = asyncio.run(
        agent.investigate(
            client,
            session,
            "fake",
            "bound.pcap",
            "检查HTTP",
            TOOLS,
            report_format="guarded",
            max_calls=1,
            max_rounds=2,
            audit=audit,
        )
    )
    assert len(client.calls) == 1 and result.model_rounds == 1
    assert "response_format" not in client.calls[0]
    assert session.calls[-1][1] == {"path": "bound.pcap", "evidence_mode": "field"}
    assert (
        result.program_report["facts"]
        == reporting.generate_report([asdict(r) for r in result.evidence])["facts"]
    )
    assert audit.data["guarded_report"]["status"] == "saved_record_facts_available"
    assert audit.data["tool_decisions"][0]["status"] == "executed"


@pytest.mark.parametrize("arguments", [
    {"pcap_file": "02.pcap"}, {"path": "other.pcap"}, {"evidence_mode": "legacy"},
])
def test_guarded_rejects_undeclared_arguments_before_server_dispatch(tmp_path, arguments):
    client = FakeClient(FakeMessage(tool_calls=[call("bad", "inspect_http_requests", arguments)]))
    session = FakeSession()
    audit = ResearchAudit(audit_path=tmp_path / "audit.json")
    result = asyncio.run(agent.investigate(
        client, session, "fake", "bound.pcap", "检查HTTP", TOOLS,
        report_format="guarded", max_calls=1, max_rounds=2, audit=audit,
    ))
    assert len(client.calls) == 1 and len(session.calls) == 1
    assert session.calls[0][0] == "summarize_capture"
    assert not result.program_report["facts"]
    assert audit.data["tool_decisions"][0]["status"] == "rejected"
    assert "schema" in audit.data["tool_decisions"][0]["error"]
    assert client.calls[0]["tools"][1]["function"]["parameters"]["additionalProperties"] is False


@pytest.mark.parametrize("raw", [
    '{"limit":true}', '{"limit":"2"}', '{"limit":0}', '{"limit":2,"extra":1}',
    '{"limit":2,"limit":3}', '{"limit":NaN}', '[]', '{}',
])
def test_guarded_argument_validation_does_not_coerce_or_repair(raw):
    schema = {
        "type": "object", "properties": {"limit": {"type": "integer", "minimum": 1}},
        "required": ["limit"], "additionalProperties": False,
    }
    with pytest.raises(ValueError):
        agent._guarded_arguments(raw, schema)


def test_guarded_schema_handles_required_nullable_and_enum_without_changing_legacy():
    schema = {
        "type": "object", "additionalProperties": False,
        "properties": {"protocol": {"enum": ["tcp", "udp"]},
                       "stream": {"anyOf": [{"type": "integer"}, {"type": "null"}]}},
        "required": ["protocol"],
    }
    value = {"protocol": "tcp", "stream": None}
    assert agent._guarded_arguments(json.dumps(value), schema) == value
    assert "additionalProperties" not in agent._focused_tools(TOOLS)[0]["function"]["parameters"]


def test_no_tools_or_unusable_evidence_is_explicit_failure_of_field_coverage():
    client = FakeClient(FakeMessage("UNVERIFIED FINDING"))
    result = asyncio.run(
        agent.investigate(
            client,
            FakeSession(),
            "fake",
            "case.pcap",
            "检查HTTP",
            TOOLS,
            report_format="guarded",
            max_calls=1,
            max_rounds=2,
        )
    )
    assert len(client.calls) == 1 and not result.program_report["facts"]
    assert "不能据此声称调查成功" in result.report
    assert "UNVERIFIED FINDING" not in result.report


@pytest.mark.parametrize("flag", ["error", "truncated"])
def test_guarded_excludes_incomplete_or_error_records(flag):
    rows = saved()
    rows[1][flag] = True
    report = agent._finish("x", "x", "", [agent.Evidence(**r) for r in rows], 1, "guarded")
    assert not report.program_report["facts"]


def test_renderer_can_withhold_all_prose_without_losing_facts():
    report = reporting.generate_report(saved())
    report["model_prose"] = {
        "hypotheses": [{"text": "UNVERIFIED TEXT", "basis": []}],
        "limitations": [],
    }
    public = reporting.render_report(report, include_model_prose=False)
    assert "UNVERIFIED TEXT" not in public
    assert "UNVERIFIED TEXT" in reporting.render_report(report)
    assert "route-client/6" in public
