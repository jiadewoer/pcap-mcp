"""Exercises the committed capture through real Wireshark binaries when installed."""

import asyncio
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pcap_mcp import config, server
from pcap_mcp.agent import investigate
from pcap_mcp.config import Settings

FIXTURE = Path(__file__).parent / "fixtures" / "injection_demo.pcap"


@pytest.mark.integration
def test_capture_is_parsed_and_http_injection_is_flagged(monkeypatch):
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        pytest.skip("Wireshark's tshark and capinfos are required")

    monkeypatch.setattr(
        config,
        "_SETTINGS",
        Settings(tshark=tshark, capinfos=capinfos, allowed_dirs=(FIXTURE.parent.resolve(),)),
    )
    summary = server.summarize_capture(str(FIXTURE))
    assert '"packets": "5"' in summary

    result = server.inspect_http_requests(str(FIXTURE))
    assert "SECURITY WARNING" in result
    assert "Ignore all previous instructions" not in result
    assert '"observed_requests": 1' in result
    assert result.endswith("</untrusted_pcap_data>")


@pytest.mark.integration
def test_agent_controls_real_mcp_with_a_simulated_model(monkeypatch):
    if not shutil.which("tshark") or not shutil.which("capinfos"):
        pytest.skip("Wireshark's tshark and capinfos are required")
    monkeypatch.setenv("PCAP_MCP_ALLOWED_DIRS", str(FIXTURE.parent.resolve()))

    class Model:
        def __init__(self):
            self.calls = 0
            self.chat = SimpleNamespace(completions=self)

        async def create(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                tool_call = SimpleNamespace(
                    id="one",
                    type="function",
                    function=SimpleNamespace(name="inspect_http_requests", arguments="{}"),
                )
                message = SimpleNamespace(
                    content=None,
                    tool_calls=[tool_call],
                    model_dump=lambda exclude_none=True: {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "one",
                                "type": "function",
                                "function": {"name": "inspect_http_requests", "arguments": "{}"},
                            }
                        ],
                    },
                )
            else:
                message = SimpleNamespace(
                    content="HTTP User-Agent 有注入警告 [E02]。",
                    tool_calls=None,
                    model_dump=lambda exclude_none=True: {
                        "role": "assistant",
                        "content": "HTTP User-Agent 有注入警告 [E02]。",
                    },
                )
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    async def run():
        parameters = StdioServerParameters(
            command=sys.executable, args=["-m", "pcap_mcp.server"], env=dict(os.environ)
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                return await investigate(
                    Model(), session, "simulated", str(FIXTURE.resolve()), "检查 HTTP", tools
                )

    report = asyncio.run(run())
    assert [item.tool for item in report.evidence] == [
        "summarize_capture",
        "inspect_http_requests",
    ]
    assert report.evidence[1].security_warning is True
    assert "Ignore all previous instructions" not in report.evidence[1].result
