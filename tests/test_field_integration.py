"""True Wireshark extraction and re-extraction; no model API is required."""

import json
import shutil
from pathlib import Path

import pytest

from pcap_mcp import config, server
from pcap_mcp.config import Settings
from pcap_mcp.provenance import capture_digest, parse_tool_payload
from pcap_mcp.verify import verify_evidence

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.integration
@pytest.mark.parametrize(
    "name,present,dots,original_dots,controls,warning",
    [
        ("normal", True, 0, 0, 0, False),
        ("plain-directive", True, 31, 0, 0, True),
        ("literal-dots", True, 0, 1, 0, False),
        ("unicode-control", True, 31, 0, 1, True),
        ("missing-user-agent", False, 0, 0, 0, False),
    ],
)
def test_real_http_fields_and_reextraction(
    monkeypatch,
    name,
    present,
    dots,
    original_dots,
    controls,
    warning,
):
    tshark, capinfos = shutil.which("tshark"), shutil.which("capinfos")
    if not tshark or not capinfos:
        pytest.skip("Wireshark tshark and capinfos are required")
    monkeypatch.setattr(
        config,
        "_SETTINGS",
        Settings(
            tshark=tshark,
            capinfos=capinfos,
            allowed_dirs=(FIXTURES.resolve(),),
        ),
    )
    path = FIXTURES / "field_cases" / f"{name}.pcap"
    digest = capture_digest(path)
    text = server.inspect_http_requests(str(path), evidence_mode="field")
    payload = parse_tool_payload(text)
    assert "error" not in payload
    assert payload["observed_requests"] == 1
    ua = next(r for r in payload["field_records"] if r["field"] == "http.user_agent")
    assert ua["frame_number"] == 4 and ua["present"] is present
    assert ua["transformations"]["middle_dots_inserted_by_server"] == dots
    assert ua["transformations"]["middle_dots_in_decoded_source"] == original_dots
    assert ua["transformations"]["unicode_controls_removed"] == controls
    assert ("SECURITY WARNING" in text) is warning
    assert "sessionid" not in text
    evidence = [{"id": "E02", "result": text, "error": False, "truncated": False}]
    checked = verify_evidence(path, evidence)
    assert checked["all_records_match"] and checked["matched_count"] == 4
    assert capture_digest(path) == digest
    assert "Ignore all previous instructions" not in json.dumps(checked)
