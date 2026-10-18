"""Process/evidence/replay boundaries with simulated source-check results."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_research import fixture_evidence

from pcap_mcp import reporting_agent_study as study
from pcap_mcp.agent import _evidence, _finish
from pcap_mcp.claims import PROPERTIES, field_registry
from pcap_mcp.lineage import MISSING, read_property
from pcap_mcp.reporting import generate_report
from pcap_mcp.research import write_json_atomic

ROOT = Path(__file__).resolve().parents[1]


def manifest(tmp_path):
    capture = tmp_path / "test.pcap"
    capture.write_bytes((ROOT / "tests/fixtures/injection_demo.pcap").read_bytes())
    path = tmp_path / "manifest.json"
    write_json_atomic(
        path,
        {
            "schema_version": 1,
            "cases": [
                {
                    "id": "fixture",
                    "capture": "test.pcap",
                    "goal": "检查 HTTP 字段",
                    "required_tools": ["summarize_capture", "inspect_http_requests"],
                    "warning_tools": ["inspect_http_requests"],
                }
            ],
        },
    )
    return path


def test_agent_plan_is_bounded_and_capture_change_blocks_run(tmp_path):
    source = manifest(tmp_path)
    root = tmp_path / "study"
    protocol = study.prepare(source, root, models=["a", "b"], repeats=2)
    assert len(protocol["planned"]) == 8
    assert protocol["max_rounds"] == 3 and protocol["transport_retries"] == 0
    (tmp_path / "test.pcap").write_bytes(b"changed")
    with pytest.raises(ValueError, match="capture changed"):
        study.validate(root)
    assert study.validate(root, source=False) == protocol


def test_process_fixture_preserves_evidence_and_replays_without_source_calls(tmp_path, monkeypatch):
    root = tmp_path / "study"
    study.prepare(manifest(tmp_path), root, models=["fixture"])
    monkeypatch.setenv("OPENAI_API_KEY", "private-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://secret.example/v1/")
    evidence = fixture_evidence()
    records = [_evidence(item["id"], item["tool"], {}, item["result"]) for item in evidence]
    calls = []

    def process(command, **kwargs):
        calls.append(command)

        def argument(name):
            return command[command.index(name) + 1]

        folder = Path(argument("--audit-json")).parent
        write_json_atomic(folder / "evidence.json", evidence)
        write_json_atomic(folder / "audit.json", {"model_rounds": 2})
        if argument("--report-format") == "program":
            raw = '{"schema_version":1,"hypotheses":[],"limitations":[]}'
            write_json_atomic(folder / "program-report.json", generate_report(evidence, raw))
            report = _finish("检查 HTTP", "test.pcap", raw, records, 2, "program").markdown()
        else:
            facts = [
                {"record": ref, "property": prop, "value": actual}
                for ref, record in field_registry(evidence).items()
                for prop in PROPERTIES
                if (actual := read_property(record, prop)) is not MISSING
            ]
            proposal = {"schema_version": 1, "facts": facts, "hypotheses": [], "limitations": []}
            write_json_atomic(folder / "claims.json", proposal)
            report = _finish(
                "检查 HTTP", "test.pcap", json.dumps(proposal), records, 2, "claims"
            ).markdown()
        (folder / "report.md").write_text(report, encoding="utf-8")
        return SimpleNamespace(
            returncode=0, stdout="private-key", stderr="http://secret.example/v1/"
        )

    monkeypatch.setattr(study.subprocess, "run", process)
    monkeypatch.setattr(
        study,
        "verify_evidence",
        lambda *args: {"record_count": 4, "matched_count": 4, "all_records_match": True},
    )
    result = study.run(root)
    assert len(calls) == 2
    assert all(command[command.index("--transport-retries") + 1] == "0" for command in calls)
    assert all(command[command.index("--reasoning-effort") + 1] == "none" for command in calls)
    assert "private-key" not in (root / "summary.json").read_text()
    monkeypatch.setattr(
        study, "verify_evidence", lambda *args: pytest.fail("Offline replay must not re-extract")
    )
    assert result == study.replay(root, root / "replayed.json")
    assert (root / "summary.json").read_bytes() == (root / "replayed.json").read_bytes()
    with pytest.raises(ValueError, match="already attempted"):
        study.run(root)
    program = next(root / row["run_id"] for row in result["trials"] if row["method"] == "program")
    path = program / "program-report.json"
    changed = study.read_json(path)
    changed["facts"][0]["value"] = "changed"
    write_json_atomic(path, changed)
    with pytest.raises(ValueError, match="changed"):
        study.replay(root)
