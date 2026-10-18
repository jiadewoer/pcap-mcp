"""Controller tests: the LLM chooses tools, but cannot change the capture or budget."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from pcap_mcp.agent import AgentError, _focused_tools, _is_error, investigate


def tool(name, properties=None):
    fields = {"path": {"type": "string"}, **(properties or {})}
    return SimpleNamespace(
        name=name,
        description=f"Run {name}",
        inputSchema={"type": "object", "properties": fields, "required": ["path"]},
    )


TOOLS = [tool("summarize_capture"), tool("inspect_dns_queries"), tool("inspect_http_requests")]


def call(identifier, name, arguments):
    return SimpleNamespace(
        id=identifier,
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


class FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_none=True):
        if self.tool_calls:
            return {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": item.id,
                        "type": item.type,
                        "function": {
                            "name": item.function.name,
                            "arguments": item.function.arguments,
                        },
                    }
                    for item in self.tool_calls
                ],
            }
        return {"role": "assistant", "content": self.content}


class FakeClient:
    def __init__(self, *messages):
        self.responses = iter(messages)
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=next(self.responses))])


class FakeSession:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        text = self.outputs.get(name, '{"truncated": false}')
        return SimpleNamespace(content=[SimpleNamespace(text=text)], isError=False)


def test_agent_binds_one_capture_and_records_evidence():
    client = FakeClient(
        FakeMessage(tool_calls=[call("c1", "inspect_dns_queries", {"path": "/elsewhere.pcap"})]),
        FakeMessage(content="观察到 DNS 流量 [E01][E02]。"),
    )
    session = FakeSession({"summarize_capture": '{"file":"sample.pcap"}'})
    result = asyncio.run(
        investigate(client, session, "test-model", "/allowed/sample.pcap", "调查 DNS", TOOLS)
    )
    assert session.calls == [
        ("summarize_capture", {"path": "/allowed/sample.pcap"}),
        ("inspect_dns_queries", {"path": "/allowed/sample.pcap"}),
    ]
    assert [item.id for item in result.evidence] == ["E01", "E02"]
    assert result.model_rounds == 2
    assert "| E02 | `inspect_dns_queries` | 完成 |" in result.markdown()
    offered = client.calls[0]["tools"]
    assert [item["function"]["name"] for item in offered] == [
        "inspect_dns_queries",
        "inspect_http_requests",
    ]
    assert "path" not in offered[0]["function"]["parameters"]["properties"]
    assert "path" not in offered[0]["function"]["parameters"]["required"]


def test_chinese_goal_repairs_english_model_report_within_round_budget():
    client = FakeClient(
        FakeMessage(tool_calls=[call("c1", "inspect_http_requests", {})]),
        FakeMessage(content="The User-Agent contains a suspicious instruction [E01][E02]."),
        FakeMessage(content="抓包中的用户代理字段包含可疑指令，需人工核对 [E01][E02]。"),
    )
    events = []
    outcome = asyncio.run(
        investigate(
            client,
            FakeSession(),
            "local",
            "sample.pcap",
            "检查 HTTP 请求",
            TOOLS,
            max_rounds=3,
            on_event=events.append,
        )
    )
    assert outcome.model_rounds == 3
    assert "用户代理字段" in outcome.report
    assert "模型未按要求使用中文" not in outcome.report
    assert "概览完成，记录 E01" in events
    assert "完成工具 inspect_http_requests，记录 E02" in events
    assert "tools" not in client.calls[-1]
    assert "简体中文" in client.calls[-1]["messages"][-1]["content"]
    assert (
        sum(
            item.get("content") == "The User-Agent contains a suspicious instruction [E01][E02]."
            for item in client.calls[-1]["messages"]
        )
        == 1
    )


def test_chinese_report_warns_when_round_budget_cannot_repair_it():
    client = FakeClient(
        FakeMessage(tool_calls=[call("c1", "inspect_http_requests", {})]),
        FakeMessage(content="The User-Agent contains an injection attempt [E02]."),
    )
    outcome = asyncio.run(
        investigate(client, FakeSession(), "local", "sample.pcap", "检查 HTTP", TOOLS, max_rounds=2)
    )
    assert outcome.model_rounds == 2
    assert "模型未按要求使用中文" in outcome.report
    assert len(client.calls) == 2


def test_rewrite_cannot_discard_existing_evidence_citations():
    client = FakeClient(
        FakeMessage(tool_calls=[call("c1", "inspect_http_requests", {})]),
        FakeMessage(content="Evidence shows an anomaly [E01][E02]."),
        FakeMessage(content="抓包显示存在可疑文本，还需要人工核对 [E01]。"),
    )
    outcome = asyncio.run(
        investigate(client, FakeSession(), "local", "sample.pcap", "检查 HTTP", TOOLS, max_rounds=3)
    )
    assert "模型未按要求使用中文" in outcome.report
    assert "[E01][E02]" in outcome.report


def test_report_language_override_and_valid_chinese_report_avoid_extra_call():
    client = FakeClient(FakeMessage(content="已完成抓包概览，当前仍需更多证据 [E01]。"))
    outcome = asyncio.run(
        investigate(
            client, FakeSession(), "local", "sample.pcap", "Check HTTP", TOOLS, report_language="zh"
        )
    )
    assert outcome.model_rounds == 1
    assert "模型未按要求使用中文" not in outcome.report
    assert len(client.calls) == 1
    with pytest.raises(ValueError, match="Report language"):
        asyncio.run(
            investigate(
                FakeClient(),
                FakeSession(),
                "local",
                "sample.pcap",
                "检查 HTTP",
                TOOLS,
                report_language="xx",
            )
        )


def test_cli_rejects_invalid_timeout_and_reports_invalid_capture(monkeypatch):
    import pcap_mcp.agent as agent
    from pcap_mcp.tshark import PcapError

    options = SimpleNamespace(request_timeout=0, capture="/bad.pcap")
    monkeypatch.setattr(agent, "_arguments", lambda: options)
    with pytest.raises(AgentError, match="request-timeout"):
        asyncio.run(agent._main())

    options.request_timeout = 120

    def deny_capture(_):
        raise PcapError("Capture denied.")

    monkeypatch.setattr(agent, "resolve_capture", deny_capture)
    with pytest.raises(AgentError, match="Capture denied"):
        asyncio.run(agent._main())


def test_invalid_or_unknown_tool_never_reaches_server_and_budget_forces_report():
    client = FakeClient(
        FakeMessage(
            tool_calls=[
                call("c1", "delete_file", {"path": "/sensitive"}),
                call("c2", "inspect_http_requests", {}),
                call("c3", "inspect_http_requests", {}),
            ]
        ),
        FakeMessage(content="基于 [E01][E02]，需要人工核验。"),
    )
    session = FakeSession()
    result = asyncio.run(
        investigate(
            client, session, "test-model", "/allowed/sample.pcap", "检查 HTTP", TOOLS, max_calls=1
        )
    )
    assert [name for name, _ in session.calls] == ["summarize_capture", "inspect_http_requests"]
    assert len(result.evidence) == 2
    tool_messages = [item for item in client.calls[-1]["messages"] if item["role"] == "tool"]
    assert len(tool_messages) == 3
    assert "Unknown or unavailable" in tool_messages[0]["content"]
    assert '"evidence_id": "E02"' in tool_messages[1]["content"]
    assert '"evidence_id": "E02"' in tool_messages[2]["content"]
    assert "tools" not in client.calls[-1]  # final synthesis cannot request more calls


def test_summary_failure_stops_before_any_model_request():
    session = FakeSession(
        {
            "summarize_capture": '<untrusted_pcap_data note="untrusted">\n'
            '{"error": "Capture refused"}\n</untrusted_pcap_data>'
        }
    )
    client = FakeClient()
    with pytest.raises(AgentError, match="Capture summary failed"):
        asyncio.run(investigate(client, session, "test-model", "bad.pcap", "目标", TOOLS))
    assert not client.calls


def test_budget_and_evidence_detection():
    assert _is_error('{"error": "failure"}')
    assert not _is_error('{"file":"sample.pcap"}')
    assert _focused_tools(TOOLS)[0]["function"]["name"] == "inspect_dns_queries"
    session = FakeSession()
    client = FakeClient()
    with pytest.raises(ValueError, match="Model rounds"):
        asyncio.run(
            investigate(client, session, "test-model", "x.pcap", "目标", TOOLS, max_rounds=1)
        )
    assert not session.calls


def test_nonexistent_evidence_citation_is_rejected():
    client = FakeClient(FakeMessage(content="不存在的发现 [E99]"))
    with pytest.raises(AgentError, match="never recorded"):
        asyncio.run(investigate(client, FakeSession(), "test-model", "x.pcap", "目标", TOOLS))


def test_context_budget_rejects_large_result_and_marks_error(monkeypatch):
    import pcap_mcp.agent as agent

    monkeypatch.setattr(agent, "MAX_TOTAL_EVIDENCE_CHARS", 60)
    client = FakeClient(
        FakeMessage(tool_calls=[call("c1", "inspect_http_requests", {})]),
        FakeMessage(content="证据不足 [E01][E02]。"),
    )
    session = FakeSession({"inspect_http_requests": "x" * 100})
    result = asyncio.run(investigate(client, session, "test-model", "x.pcap", "目标", TOOLS))
    assert result.evidence[1].error is True
    assert "context budget" in result.evidence[1].result
    assert result.model_rounds == 2
