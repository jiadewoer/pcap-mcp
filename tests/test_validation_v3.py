"""Meaningful controller, protocol identity, integrity and budget boundaries."""

import asyncio
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_research import fixture_evidence
from test_research_agent import Client, Message, Session, http_call, tools

from pcap_mcp import config, frozen_prose, validation, validation_cases
from pcap_mcp.config import Settings
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.research import ResearchAudit
from pcap_mcp.validation_agent import collect

ROOT = Path(__file__).resolve().parents[1]
VALID_PROSE = json.dumps(
    {
        "schema_version": 1,
        "hypotheses": [],
        "limitations": ["导出记录不证明原始字符编码、网络对端意图或攻击成功。"],
    },
    ensure_ascii=False,
)


def test_frozen_v3_matches_saved_wire_requests():
    # Golden requests are byte-for-byte copies from the supplied real v3 run.
    # Do not import old development runners and their unrelated legacy files.
    folder = ROOT / "tests/fixtures/frozen-v3-wire"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert {row["arm"] for row in manifest["requests"]} == set(frozen_prose.ARMS)
    for row in manifest["requests"]:
        raw = (folder / row["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        expected = json.loads(raw)
        payload = json.loads(expected["messages"][1]["content"])
        assert frozen_prose.request(
            expected["model"], payload["goal"], payload["evidence"], row["arm"]
        ) == expected


@pytest.mark.parametrize(
    "text,valid,refs",
    [
        (VALID_PROSE, True, True),
        ('{"schema_version":true,"hypotheses":[],"limitations":[]}', False, False),
        ('{"schema_version":1,"schema_version":1,"hypotheses":[],"limitations":[]}', False, False),
        ("```json\n" + VALID_PROSE + "\n```", False, False),
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "hypotheses": [
                        {
                            "text": "未证实解释",
                            "basis": [
                                "E02/F4:http.user_agent/0.transformations.unicode_controls_removed"
                            ],
                        }
                    ],
                    "limitations": [],
                }
            ),
            True,
            False,
        ),
        (
            json.dumps({"schema_version": 1, "hypotheses": [], "limitations": ["x" * 4001]}),
            False,
            False,
        ),
    ],
)
def test_strict_local_gate_does_not_repair_format_or_reference(text, valid, refs):
    result = frozen_prose.metrics(fixture_evidence(), text)
    assert result["structure_valid"] is valid and result["references_valid"] is refs
    assert result["closed_facts_unchanged"]
    assert result["semantic_correctness"] == "pending_manual_review"


def test_empty_and_missing_evidence_are_not_success():
    data = frozen_prose.metrics(
        fixture_evidence(), '{"schema_version":1,"hypotheses":[],"limitations":[" "]}'
    )
    assert data["structure_valid"] and data["empty_prose"] and not data["nonempty_limitations"]
    with pytest.raises(ValueError, match="No allowed"):
        frozen_prose.request("fake", "goal", [], "explicit_json")


def test_early_narrative_is_not_used_as_final_prose(tmp_path):
    client = Client(Message(content=VALID_PROSE))
    result = asyncio.run(
        collect(
            Session(),
            tools(),
            "bound.pcap",
            "目标",
            "fake",
            lambda request, phase: client.create(**request),
            ResearchAudit(tmp_path / "evidence.json"),
        )
    )
    assert len(result) == 1 and result[0]["id"] == "E01"
    assert len(client.requests) == 1


def test_controller_binds_path_mode_and_reuses_duplicate_tool(tmp_path):
    second = deepcopy(http_call())
    second.id = "second"
    client = Client(Message(tool_calls=[http_call(), second]), Message(content="完成"))
    session = Session()
    result = asyncio.run(
        collect(
            session,
            tools(),
            "bound.pcap",
            "目标",
            "fake",
            lambda request, phase: client.create(**request),
            ResearchAudit(),
        )
    )
    assert len(result) == 2
    assert session.calls == [
        ("summarize_capture", {"path": "bound.pcap"}),
        ("inspect_http_requests", {"path": "bound.pcap", "evidence_mode": "field"}),
    ]
    assert len(client.requests) == 2
    assert "path" not in client.requests[0]["tools"][0]["function"]["parameters"]["properties"]


def test_hard_budget_counts_failed_attempts(tmp_path):
    budget = validation.Budget(1, tmp_path / "requests", lambda text: text)
    client = Client(RuntimeError("provider failure"), Message(content="must not be called"))
    req = {"model": "fake", "reasoning_effort": "none", "messages": []}
    with pytest.raises(RuntimeError):
        asyncio.run(budget.send(client, req, "g", "decision"))
    with pytest.raises(ValueError, match="budget"):
        asyncio.run(budget.send(client, req, "g", "final"))
    assert len(client.requests) == budget.attempts == 1
    saved = validation.read(tmp_path / "requests/request-001.json")
    assert saved["status"] == "failed" and saved["error_type"] == "RuntimeError"
    assert "provider failure" not in json.dumps(saved)


def test_generated_pcaps_are_deterministic_and_checksums_independently_valid(tmp_path):
    first = validation_cases.generate(tmp_path / "a")
    second = validation_cases.generate(tmp_path / "b")
    assert first.read_bytes() == second.read_bytes()
    for path in first.parent.glob("*.pcap"):
        data = path.read_bytes()
        assert data == (second.parent / path.name).read_bytes()
        offset = 24
        count = 0
        while offset < len(data):
            _, _, size, original_size = struct.unpack_from("<IIII", data, offset)
            frame = data[offset + 16 : offset + 16 + size]
            assert size == original_size == len(frame)
            ip, tcp = frame[14:34], frame[34:]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
            for part in (ip, pseudo + tcp):
                padded = part + (b"\0" if len(part) % 2 else b"")
                total = sum(
                    int.from_bytes(padded[i : i + 2], "big") for i in range(0, len(padded), 2)
                )
                while total >> 16:
                    total = (total & 65535) + (total >> 16)
                assert total == 65535
            count += 1
            offset += 16 + size
        assert offset == len(data) and count in {5, 10}


def test_plan_rejects_large_batch_before_wireshark_or_writes(tmp_path):
    manifest = validation_cases.generate(tmp_path / "fixtures")
    with pytest.raises(ValueError, match="at most 32"):
        validation.prepare(manifest, tmp_path / "run", models=["fake"], smoke=False)
    assert not (tmp_path / "run").exists()
    with pytest.raises(ValueError, match="at most 16"):
        validation.prepare(manifest, tmp_path / "run", models=["first", "second"])


def test_parent_capture_scope_restores_cached_permissions(tmp_path):
    previous = Settings(tshark="fixture", capinfos="fixture", allowed_dirs=(), redact=False)
    config._SETTINGS = previous
    with validation.capture_scope(tmp_path / "capture.pcap"):
        assert config.get_settings().allowed_dirs == (tmp_path.resolve(),)
        assert config.get_settings().redact
    assert config._SETTINGS is previous


class FixtureModel:
    """Response transport stub; never represented as a real model result."""

    def __init__(self, *, fail_final=False):
        self.requests = []
        self.decisions = 0
        self.fail_final = fail_final
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self, **request):
        self.requests.append(deepcopy(request))
        if "tools" in request:
            self.decisions += 1
            message = (
                Message(tool_calls=[http_call()])
                if self.decisions % 2
                else Message(content="停止调查")
            )
        else:
            if self.fail_final:
                raise RuntimeError("simulated response failure")
            message = Message(content=VALID_PROSE)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


@pytest.mark.integration
def test_actual_mcp_eight_new_captures_and_offline_replay(tmp_path, monkeypatch):
    if not shutil.which("tshark") or not shutil.which("capinfos"):
        pytest.skip("Wireshark required")
    manifest = validation_cases.generate(tmp_path / "fixtures")
    root = tmp_path / "run"
    protocol = validation.prepare(
        manifest,
        root,
        models=["simulated-transport"],
        smoke=False,
        max_requests=32,
        environment={"model_backend": "test_stub_not_real_model"},
    )
    assert all(c["preflight_ok"] for c in protocol["cases"])
    client = FixtureModel()
    result = asyncio.run(validation.run(root, client))
    assert len(client.requests) == result["totals"]["model_request_attempts"] == 32
    assert result["totals"]["planned_prose_trials"] == 16
    assert result["totals"]["program_complete_and_source_verified"] == 16
    assert result["totals"]["synthetic_oracle_matched"] == 16
    assert result["totals"]["semantic_accepted"] is None
    for group in protocol["groups"]:
        requests = [
            validation.read(root / group["id"] / arm / "request.json") for arm in group["arms"]
        ]
        assert {k: v for k, v in requests[0].items() if k != "response_format"} == {
            k: v for k, v in requests[1].items() if k != "response_format"
        }
    monkeypatch.setattr(
        client.chat.completions, "create", lambda **kwargs: pytest.fail("replay called model")
    )
    assert validation.replay(root) == result
    assert validation.replay(root, source=True) == result
    reviewed = validation.review(root, root / "review-template.json")
    assert reviewed == {
        "planned": 16,
        "pending": 16,
        "approved": 0,
        "rejected": 0,
        "scope": "human_review_of_saved_prose_not_general_model_accuracy",
    }
    with pytest.raises(FileExistsError):
        asyncio.run(validation.run(root, client))
    (root / "group-001/evidence.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact changed"):
        validation.replay(root)


def test_failed_and_unattempted_trials_stay_in_denominator(tmp_path, monkeypatch):
    manifest = validation_cases.generate(tmp_path / "fixtures")
    payload = parse_tool_payload(fixture_evidence()[1]["result"])
    config._SETTINGS = Settings(tshark="fake", capinfos="fake", allowed_dirs=(tmp_path,))
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="fixture version\n")
    )
    monkeypatch.setattr(validation, "http_field_evidence", lambda path: payload)
    monkeypatch.setattr(
        validation_cases, "check_oracle", lambda *a: {"status": "not_provided", "matched": None}
    )
    root = tmp_path / "run"
    protocol = validation.prepare(manifest, root, models=["fake"])
    assert validation.replay(root)["totals"]["planned_prose_trials"] == 4
    assert validation.replay(root)["totals"]["model_request_attempts"] == 0

    @asynccontextmanager
    async def fake_session(path):
        yield Session()

    monkeypatch.setattr(
        validation, "verify_evidence", lambda *args: {"all_records_match": True, "matched_count": 4}
    )
    client = FixtureModel(fail_final=True)
    result = asyncio.run(validation.run(root, client, session_factory=fake_session))
    assert result["totals"]["planned_prose_trials"] == 4
    assert result["totals"]["completed_prose_responses"] == 0
    assert result["totals"]["model_request_attempts"] == len(client.requests) == 8
    assert all(t["status"] == "request_failed" for t in result["trials"])
    assert validation.replay(root) == result
    assert validation.read(root / "protocol.json") == protocol


def test_comparison_keeps_missing_pairs_and_models_separate():
    rows = []
    for model in ("one", "two"):
        for case in ("a", "b"):
            for arm in frozen_prose.ARMS:
                valid = model == "one" and case == "a"
                rows.append(
                    {
                        "model": model,
                        "case_id": case,
                        "arm": arm,
                        "status": "completed" if valid else "unattempted",
                        "prose": {"references_valid": True} if valid else None,
                    }
                )
    data = validation.compare_conditions(rows, ["one", "two"])
    assert [row["planned_pairs"] for row in data["paired_counts"]] == [2, 2]
    assert data["paired_counts"][0]["both_valid"] == 1
    assert data["paired_counts"][1]["neither_valid_or_missing"] == 2
    assert all(
        row["planned"] == 2 and row["semantic_accepted"] is None for row in data["by_model_and_arm"]
    )


@pytest.mark.parametrize("bad_id", ["../../escape", "", "重复", "two words"])
def test_manifest_rejects_invalid_case_identifiers(tmp_path, bad_id):
    manifest = validation_cases.generate(tmp_path / "fixtures")
    data = validation.read(manifest)
    data["cases"][0]["id"] = bad_id
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="case id"):
        validation_cases.load(manifest)


def test_additive_installer_refuses_conflicts_and_applies_no_partial_update(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "validation_installer", ROOT / "validation-v3/apply_update.py"
    )
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    project, package = tmp_path / "project", tmp_path / "package"
    (project / "src").mkdir(parents=True)
    (package / "payload/src").mkdir(parents=True)
    (project / "pyproject.toml").write_text("original", encoding="utf-8")
    # This is a byte-preservation fixture. Text mode would turn CRLF into
    # CRCRLF on Windows before the installer even runs.
    (project / "src/old.py").write_bytes(b"old\r\n")
    (package / "payload/src/first.py").write_text("first\n", encoding="utf-8")
    (package / "payload/src/second.py").write_text("second\n", encoding="utf-8")
    manifest = {
        "version": validation.VERSION,
        "base_sha256_normalized": {"src/old.py": installer.digest(project / "src/old.py")},
        "files": [
            {
                "path": "src/" + name + ".py",
                "sha256_normalized": installer.digest(package / "payload/src" / (name + ".py")),
            }
            for name in ("first", "second")
        ],
    }
    (package / "update-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (project / "src/second.py").write_text("local edit", encoding="utf-8")
    with pytest.raises(ValueError, match="Existing file differs"):
        installer.apply(project, package)
    assert not (project / "src/first.py").exists()
    assert (project / "src/second.py").read_text() == "local edit"
    (project / "src/second.py").unlink()
    installer.apply(project, package, check=True)
    assert not (project / "src/first.py").exists()
    installer.apply(project, package)
    installer.apply(project, package)  # Idempotent rerun, no writes to old source.
    assert (project / "src/first.py").read_text() == "first\n"
    assert (project / "src/old.py").read_bytes() == b"old\r\n"
    with pytest.raises(ValueError, match="Unsafe"):
        installer.safe(project, "src/../../outside.py")
