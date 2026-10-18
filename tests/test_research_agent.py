"""Bounded controller behavior with simulated model/MCP responses."""

import asyncio
import json
import tempfile
import unittest
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_research import claim_data, fixture_evidence

from pcap_mcp import agent
from pcap_mcp.agent import AgentError, investigate
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.research import ResearchAudit, expand_record


class Message:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []

    def model_dump(self, **kwargs):
        result = {"role": "assistant"}
        if self.content is not None:
            result["content"] = self.content
        if self.tool_calls:
            result["tool_calls"] = [{
                "id": call.id, "type": call.type,
                "function": {"name": call.function.name, "arguments": call.function.arguments},
            } for call in self.tool_calls]
        return result


def http_call():
    return SimpleNamespace(id="call-http", type="function", function=SimpleNamespace(
        name="inspect_http_requests", arguments=json.dumps(
            {
                "path": "other.pcap",
                 "evidence_mode": "legacy"
            }
        ),
    ))


class Client:
    def __init__(self, *messages):
        self.messages = list(messages)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self, **request):
        self.requests.append(deepcopy(request))
        if not self.messages:
            raise AssertionError("Unexpected additional model request")
        message = self.messages.pop(0)
        if isinstance(message, Exception):
            raise message
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def tools():
    return [
        SimpleNamespace(
            name=name,
             description="fixture",
             inputSchema={
                "type": "object",
                 "properties": {
                    "path": {
                        "type": "string"
                    }
                }
            }
        ) for name in (
            "summarize_capture",
             "inspect_http_requests"
        )
    ]


class Session:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        data = fixture_evidence()
        text = data[0 if name == "summarize_capture" else 1]["result"]
        return SimpleNamespace(content=[SimpleNamespace(text=text)], isError=False)

    async def initialize(self):
        pass

    async def list_tools(self):
        return SimpleNamespace(tools=tools())


class ControllerResearchTests(unittest.TestCase):
    def test_oversized_flat_view_fails_after_source_checkpoint(self):
        client = Client(Message(tool_calls=[http_call()]))
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "evidence.json"
            with patch.object(agent, "model_view", return_value="x" * 50_001):
                with self.assertRaisesRegex(AgentError, "model-view budget"):
                    asyncio.run(investigate(
                        client, Session(), "fake", "bound.pcap", "检查 HTTP", tools(),
                        evidence_view="flat", audit=ResearchAudit(path),
                    ))
            self.assertEqual(len(json.loads(path.read_text())), 2)
            self.assertEqual(len(client.requests), 1)

    def test_format_repair_respects_three_rounds_and_does_not_fix_false_values(self):
        data = claim_data(
            [
                {
                    "record": "E02/F4:http.user_agent/0",
                     "property": "transformations.unicode_controls_removed",
                     "value": 1
                }
            ]
        )
        client = Client(
            Message(
                tool_calls=[
                    http_call(
                    )
                ]
            ),
             Message(
                '{"facts":[]}'
            ),
             Message(
                json.dumps(
                    data
                )
            )
        )
        session = Session()
        with tempfile.TemporaryDirectory() as name:
            audit = ResearchAudit(Path(name) / "evidence.json", Path(name) / "audit.json")
            result = asyncio.run(
                investigate(
                    client,
                     session,
                     "fake",
                     "bound.pcap",
                     "检查 HTTP",
                     tools(
                    ),
                     max_rounds=3,
                     report_format="claims",
                     audit=audit
                )
            )
            self.assertEqual(result.model_rounds, 3)
            self.assertEqual(len(client.requests), 3)
            self.assertEqual(len(session.calls), 2)
            self.assertEqual(session.calls[-1][1], {"path": "bound.pcap", "evidence_mode": "field"})
            self.assertNotIn("response_format", client.requests[0])
            self.assertEqual(client.requests[1]["response_format"], {"type": "json_object"})
            self.assertEqual(client.requests[2]["response_format"], {"type": "json_object"})
            self.assertFalse(result.claim_checks["facts"][0]["accepted"])
            self.assertEqual(audit.data["format_repair_requests"], 1)
            self.assertFalse(audit.data["format_first_pass_valid"])
            self.assertTrue(audit.data["responses"][-1]["format_valid"])

    def test_invalid_second_attempt_fails_without_extra_model_calls(self):
        client = Client(Message(tool_calls=[http_call()]), Message("bad"), Message("still bad"))
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            audit = ResearchAudit(root / "evidence.json", root / "audit.json")
            with self.assertRaises(AgentError):
                asyncio.run(
                    investigate(
                        client,
                         Session(
                        ),
                         "fake",
                         "bound.pcap",
                         "检查 HTTP",
                         tools(
                        ),
                         max_rounds=3,
                         report_format="claims",
                         audit=audit
                    )
                )
            self.assertEqual(len(client.requests), 3)
            self.assertEqual(len(json.loads((root / "evidence.json").read_text())), 2)
            self.assertEqual(audit.data["format_attempts"], 2)

    def test_retries_disabled_and_prompt_mode_are_explicit(self):
        client = Client(Message(tool_calls=[http_call()]), Message("bad"))
        with self.assertRaises(AgentError):
            asyncio.run(
                investigate(
                    client,
                     Session(
                    ),
                     "fake",
                     "bound.pcap",
                     "检查 HTTP",
                     tools(
                    ),
                     max_rounds=2,
                     report_format="claims",
                     max_format_retries=0,
                     claims_response_format="prompt"
                )
            )
        self.assertEqual(len(client.requests), 2)
        self.assertNotIn("response_format", client.requests[-1])

    def test_valid_but_wrong_fact_is_rejected_without_format_retry(self):
        data = claim_data(
            [
                {
                    "record": "E02/F4:http.user_agent/0",
                     "property": "present",
                     "value": False
                }
            ]
        )
        client = Client(Message(tool_calls=[http_call()]), Message(json.dumps(data)))
        result = asyncio.run(
            investigate(
                client,
                 Session(
                ),
                 "fake",
                 "bound.pcap",
                 "检查 HTTP",
                 tools(
                ),
                 max_rounds=3,
                 report_format="claims"
            )
        )
        self.assertFalse(result.claim_checks["all_facts_accepted"])
        self.assertEqual(len(client.requests), 2)

    def test_flat_model_view_does_not_change_saved_evidence(self):
        client = Client(Message(tool_calls=[http_call()]), Message("User-Agent 值见证据 [E02]。"))
        result = asyncio.run(
            investigate(
                client,
                 Session(
                ),
                 "fake",
                 "bound.pcap",
                 "检查 HTTP",
                 tools(
                ),
                 max_calls=1,
                 evidence_view="flat"
            )
        )
        raw = parse_tool_payload(result.evidence[-1].result)
        sent = json.loads(
            next(
                m[
                    "content"
                ] for m in client.requests[
                    -1
                ][
                    "messages"
                ] if m[
                    "role"
                ] == "tool"
            )
        )
        projected = parse_tool_payload(sent["result"])
        self.assertEqual(
            raw[
                "field_records"
            ],
             [
                expand_record(
                    record
                ) for record in projected[
                    "field_records"
                ]
            ]
        )
        self.assertIn("transformations", raw["field_records"][-1])
        self.assertNotIn("transformations", projected["field_records"][-1])

    def test_empty_facts_does_not_become_research_success(self):
        client = Client(Message(tool_calls=[http_call()]), Message(json.dumps(claim_data())))
        result = asyncio.run(
            investigate(
                client,
                 Session(
                ),
                 "fake",
                 "bound.pcap",
                 "检查 HTTP",
                 tools(
                ),
                 report_format="claims",
                 max_rounds=3
            )
        )
        self.assertFalse(result.claim_checks["all_facts_accepted"])
        self.assertEqual(result.claim_checks["statistics"]["user_agent_predicate_coverage"], 0)

    def test_request_error_still_keeps_http_evidence(self):
        client = Client(
            Message(
                tool_calls=[
                    http_call(
                    )
                ]
            ),
             RuntimeError(
                "simulated request failure"
            )
        )
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "evidence.json"
            with self.assertRaises(RuntimeError):
                asyncio.run(
                    investigate(
                        client,
                         Session(
                        ),
                         "fake",
                         "bound.pcap",
                         "检查 HTTP",
                         tools(
                        ),
                         max_calls=1,
                         audit=ResearchAudit(
                            path
                        )
                    )
                )
            self.assertEqual(json.loads(path.read_text())[1]["tool"], "inspect_http_requests")

    def test_cli_failure_marks_checkpoint_and_redacts_credentials(self):
        client = Client(
            Message(
                tool_calls=[
                    http_call(
                    )
                ]
            ),
             Message(
                "private-key bad JSON"
            ),
             Message(
                "bad again"
            )
        )
        session = Session()

        @asynccontextmanager
        async def transport(*args):
            yield None, None

        @asynccontextmanager
        async def context(*args):
            yield session

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            arguments = SimpleNamespace(
                request_timeout=120,
                 capture="bound.pcap",
                 claims_json=root / "claims.json",
                 report_format="claims",
                 quiet=True,
                 evidence_json=root / "evidence.json",
                 audit_json=root / "audit.json",
                 goal="检查 HTTP",
                 max_calls=2,
                 max_rounds=3,
                 report_language="zh",
                 evidence_mode="field",
                 evidence_view="structured",
                 max_format_retries=1,
                 claims_response_format="json",
                 temperature=0.0,
                 seed=0,
                 output=root / "report.md"
            )
            with (
                patch.object(
                    agent,
                     "_arguments",
                     return_value=arguments
                ),
                 patch.object(
                    agent,
                     "resolve_capture",
                     return_value=Path(
                        "bound.pcap"
                    )
                ),
                 patch.object(
                    agent,
                     "AsyncOpenAI",
                     return_value=client
                ),
                 patch.object(
                    agent,
                     "stdio_client",
                     transport
                ),
                 patch.object(
                    agent,
                     "ClientSession",
                     context
                ),
                 patch.dict(
                    "os.environ",
                     {
                        "OPENAI_API_KEY": "private-key",
                         "OPENAI_BASE_URL": "http://localhost/v1/",
                         "OPENAI_MODEL": "fake"
                    }
                )
            ):
                with self.assertRaises(AgentError):
                    asyncio.run(agent._main())
            audit = json.loads((root / "audit.json").read_text())
            self.assertEqual(audit["status"], "failed")
            self.assertEqual(audit["error_type"], "AgentError")
            self.assertNotIn("private-key", json.dumps(audit))
            self.assertFalse((root / "report.md").exists())
            self.assertTrue((root / "evidence.json").is_file())


if __name__ == "__main__":
    unittest.main()
