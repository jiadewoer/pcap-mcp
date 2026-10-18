"""Boundary checks for program facts and the bounded Agent integration."""

import asyncio
import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_research_agent import Client, Message, Session, http_call, tools

from pcap_mcp.agent import investigate
from pcap_mcp.lineage import build_suite, evidence_for
from pcap_mcp.reporting import decode_prose, generate_report, render_report

ROOT = Path(__file__).resolve().parents[1]
PROSE = '{"schema_version":1,"hypotheses":[],"limitations":[]}'


def one_record():
    return deepcopy(build_suite(ROOT / "benchmarks/lineage")["cases"][0]["records"][0])


@pytest.mark.parametrize(
    "inserted,source,label",
    [
        (0, 0, "none"),
        (1, 0, "analysis_program"),
        (0, 2, "decoded_source"),
        (2, 3, "both"),
        (None, 0, "unknown"),
        (0, None, "unknown"),
        (True, 0, "unknown"),
        (0, False, "unknown"),
        ("0", 0, "unknown"),
        (0.0, 0, "unknown"),
        (-1, 3, "unknown"),
    ],
)
@pytest.mark.parametrize(
    "control,control_label",
    [(0, "no"), (2, "yes"), (None, "unknown"), (False, "unknown"), (-1, "unknown")],
)
def test_counter_boundaries_keep_missing_distinct_from_zero(
    inserted, source, label, control, control_label
):
    record = one_record()
    for key, value in [
        ("middle_dots_inserted_by_server", inserted),
        ("middle_dots_in_decoded_source", source),
        ("unicode_controls_removed", control),
    ]:
        if value is None:
            record["transformations"].pop(key, None)
        else:
            record["transformations"][key] = value
    report = generate_report(evidence_for({"records": [record]}))
    assert [item["value"] for item in report["attributions"]] == [label, control_label]
    for fact in report["facts"]:
        if fact["property"].startswith("transformations.") and "dots" in fact["property"]:
            assert type(fact["value"]) is int and fact["value"] >= 0


def test_empty_array_and_boolean_keep_native_types_and_no_gold_is_read():
    record = one_record()
    record["injection_kinds"] = []
    case = {"records": [record], "gold": "deliberately unusable"}
    facts = generate_report(evidence_for(case))["facts"]
    assert next(item["value"] for item in facts if item["property"] == "injection_kinds") == []
    assert type(next(item["value"] for item in facts if item["property"] == "present")) is bool


def test_duplicate_or_mismatched_locators_fail_closed():
    record = one_record()
    with pytest.raises(ValueError, match="Duplicate"):
        generate_report(evidence_for({"records": [record, record]}))
    record["occurrence"] = 2
    with pytest.raises(ValueError, match="locator"):
        generate_report(evidence_for({"records": [record]}))


def test_error_truncation_and_empty_records_do_not_become_full_success():
    evidence = evidence_for({"records": [one_record()]})
    evidence[0]["truncated"] = True
    report = generate_report(evidence)
    assert report["facts"] == [] and report["excluded_evidence"]
    assert "未获得可用字段事实" in render_report(report)
    evidence[0]["truncated"] = False
    evidence[0]["result"] = evidence[0]["result"].replace('"truncated": false', '"truncated": true')
    assert generate_report(evidence)["facts"] == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{}",
        "null",
        "[]",
        "NaN",
        "1e1000",
        PROSE.replace('"schema_version":1', '"schema_version":true'),
        PROSE.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
        PROSE[:-1] + ',"facts":[]}',
        "```json\n" + PROSE + "\n```",
    ],
)
def test_bad_prose_is_a_separate_failure_and_never_changes_program_facts(text):
    evidence = evidence_for({"records": [one_record()]})
    report = generate_report(evidence, text)
    assert report["prose_status"] == "invalid_model_output"
    assert report["facts"] == generate_report(evidence)["facts"]
    with pytest.raises((ValueError, TypeError)):
        decode_prose(text)


def test_prose_unknown_refs_and_markdown_input_are_visible_and_escaped():
    record = one_record()
    record["display_value"] = "<script>fake</script>`|\n## forged"
    prose = json.dumps(
        {
            "schema_version": 1,
            "hypotheses": [{"text": "unverified", "basis": ["E99/x"]}],
            "limitations": [],
        }
    )
    report = generate_report(evidence_for({"records": [record]}), prose)
    assert report["unknown_prose_references"] == ["E99/x"]
    rendered = render_report(report)
    assert "<script>" not in rendered and "\n## forged" not in rendered
    assert "[E02]" in rendered


def test_real_controller_uses_program_output_and_effort_for_all_model_rounds():
    client = Client(Message(tool_calls=[http_call()]), Message(PROSE))
    result = asyncio.run(
        investigate(
            client,
            Session(),
            "fake",
            "bound.pcap",
            "检查 HTTP",
            tools(),
            max_rounds=3,
            report_format="program",
            reasoning_effort="none",
        )
    )
    assert result.program_report["prose_status"] == "valid_unverified"
    assert result.program_report["facts"]
    assert result.claims is None
    assert len(client.requests) == 2
    assert all(row["extra_body"] == {"reasoning_effort": "none"} for row in client.requests)
    assert "字段事实由程序生成" in result.markdown()


def test_program_empty_final_content_does_not_trigger_repair_or_reasoning_fallback():
    client = Client(Message(tool_calls=[http_call()]), Message(None))
    result = asyncio.run(
        investigate(
            client,
            Session(),
            "fake",
            "bound.pcap",
            "检查 HTTP",
            tools(),
            max_rounds=2,
            report_format="program",
        )
    )
    assert result.program_report["prose_status"] == "invalid_model_output"
    assert result.program_report["facts"]
    assert len(client.requests) == 2
    assert all("extra_body" not in row for row in client.requests)


def test_excessive_json_nesting_is_retained_as_prose_failure():
    report = generate_report(
        evidence_for({"records": [one_record()]}), "[" * 2000 + "0" + "]" * 2000
    )
    assert report["prose_status"] == "invalid_model_output"
    assert report["facts"]
