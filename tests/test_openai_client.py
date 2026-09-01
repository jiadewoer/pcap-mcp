from types import SimpleNamespace

import pytest

from scripts.openai_mcp_client import mcp_result_text, openai_tools, required_env


def test_required_env(monkeypatch):
    monkeypatch.setenv("EXAMPLE_SETTING", " value ")
    assert required_env("EXAMPLE_SETTING") == "value"
    monkeypatch.delenv("EXAMPLE_SETTING")
    with pytest.raises(RuntimeError, match="EXAMPLE_SETTING"):
        required_env("EXAMPLE_SETTING")


def test_mcp_tools_are_converted_to_openai_schema():
    source = SimpleNamespace(
        name="summarize_capture",
        description="Start here",
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    result = openai_tools([source])
    assert result[0]["function"]["name"] == "summarize_capture"
    assert result[0]["function"]["parameters"] == source.inputSchema


def test_tool_result_is_bounded():
    result = SimpleNamespace(content=[SimpleNamespace(text="x" * 60_000)], isError=False)
    text = mcp_result_text(result)
    assert len(text) < 60_000
    assert "output limit reached" in text
