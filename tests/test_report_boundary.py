"""Publication and saved-record boundaries; fixture reviews are not real model evaluation."""

import importlib.util
import json
import socket
from copy import deepcopy
from pathlib import Path

import pytest
from test_research import fixture_evidence

from pcap_mcp import validation
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.research import canonical_digest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "report_boundary", ROOT / "report-boundary/report_boundary.py"
)
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)
TEXT = json.dumps(
    {"schema_version": 1, "hypotheses": [], "limitations": ["记录不证明原编码或攻击成功。"]},
    ensure_ascii=False,
)


def changed_evidence(change):
    evidence = fixture_evidence()
    payload = parse_tool_payload(evidence[1]["result"])
    change(payload)
    evidence[1]["result"] = (
        '<untrusted_pcap_data note="fixture">\n'
        + json.dumps(payload, ensure_ascii=False)
        + "\n</untrusted_pcap_data>"
    )
    return evidence


def proof(facts, capture=None):
    refs = facts["usable_field_references"]
    return {
        "schema_version": 1,
        "scope": "decoded_http_fields_and_transformations_not_intent_or_success",
        "coverage": "only_exported_field_occurrences_not_entire_capture",
        "capture_sha256": capture or next(iter(facts["capture_sha256_by_evidence"].values())),
        "capture_unchanged_during_verification": True,
        "all_records_match": True,
        "record_count": len(refs),
        "matched_count": len(refs),
        "records": [{"reference": r, "matched": True, "status": "matched"} for r in refs],
    }


def decision(kind="human", value="approved"):
    return {
        "decision": value,
        "reviewer_kind": kind,
        "reviewer": "fixture reviewer",
        "note": "controlled test only",
        "labels": [],
    }


@pytest.fixture
def study(tmp_path):
    """A sealed offline fixture. The certificate here is a stub, not a real source check."""
    root = tmp_path / "study"
    (root / "inputs").mkdir(parents=True)
    capture = root / "inputs/fixture.pcap"
    capture.write_bytes(b"controlled local fixture; not a packet capture")
    evidence = changed_evidence(lambda p: p.update(capture_sha256=boundary.sha(capture)))
    facts = boundary.program_facts(evidence)
    protocol = {
        "study_version": validation.VERSION,
        "code_sha256": validation.fingerprints(),
        "models": ["fixture-not-a-real-model"],
        "data_origin": "unit_fixture_not_model_run",
        "cases": [
            {
                "id": "fixture",
                "capture": "inputs/fixture.pcap",
                "capture_sha256": boundary.sha(capture),
            }
        ],
        "groups": [
            {
                "id": "group-001",
                "case_id": "fixture",
                "model": "fixture-not-a-real-model",
                "arms": ["explicit_json", "explicit_compact_schema"],
            }
        ],
        "scope": "unit_fixture_not_model_run",
    }
    boundary.write_json(root / "protocol.json", protocol)
    (root / "protocol.sha256").write_text(canonical_digest(protocol), encoding="ascii")
    group = root / "group-001"
    group.mkdir()
    boundary.write_json(group / "evidence.json", evidence)
    boundary.write_json(group / "source-verification.json", proof(facts, boundary.sha(capture)))
    for arm in protocol["groups"][0]["arms"]:
        (group / arm).mkdir()
        boundary.write_json(group / arm / "status.json", {"status": "completed"})
        boundary.write_json(group / arm / "request.json", {"fixture": True})
        (group / arm / "response.txt").write_text(TEXT, encoding="utf-8")
    boundary.write_json(root / "summary.json", validation.summary(root, protocol))
    seal(root)
    return root


def seal(root):
    boundary.write_json(
        root / "artifact-sha256.json",
        {
            p.relative_to(root).as_posix(): boundary.sha(p)
            for p in root.rglob("*")
            if p.is_file() and p.name != "artifact-sha256.json"
        },
    )


def test_offline_default_withholds_prose_preserves_bytes_and_frozen_replay(
    study, tmp_path, monkeypatch
):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("offline task opened socket"))
    before = {p: boundary.sha(p) for p in study.rglob("*") if p.is_file()}
    old_replay = validation.replay(study)
    output = tmp_path / "publication"
    result = boundary.publish(study, output)
    assert result["totals"]["new_model_requests"] == 0
    assert result["totals"]["model_bodies_withheld"] == 2
    assert result["totals"]["model_bodies_included"] == 0
    raw = output / "review-only/group-001/explicit_json/response-original.txt"
    assert raw.read_bytes() == (study / "group-001/explicit_json/response.txt").read_bytes()
    rendered = (output / "group-001/report.md").read_text(encoding="utf-8")
    assert "记录不证明原编码或攻击成功。" not in rendered
    assert result["trials"][0]["included_model_prose"] is None
    assert {p: boundary.sha(p) for p in before} == before
    assert validation.replay(study) == old_replay
    assert "original" not in result["study_binding"]


@pytest.mark.parametrize("value", [None, True, -1, "0", 0.5])
def test_invalid_or_missing_count_is_unknown_not_zero(value):
    def mutate(payload):
        counters = payload["field_records"][-1]["transformations"]
        if value is None:
            del counters["unicode_controls_removed"]
        else:
            counters["unicode_controls_removed"] = value

    facts = boundary.program_facts(changed_evidence(mutate))
    row = facts["user_agent_records"][0]
    assert "transformations.unicode_controls_removed" not in row["facts"]
    assert not facts["required_user_agent_predicates_complete"]
    report = boundary.render_group(
        {
            "case_id": "fixture",
            "facts": facts,
            "source_check": {"saved_exact_reextraction_verified": False},
        },
        [],
    )
    assert "控制字符计数：未知" in report
    assert "本分析程序没有记录控制字符移除" not in report


@pytest.mark.parametrize("present,phrase", [(True, "存在且显示为空"), (False, "未出现。")])
def test_absent_field_differs_from_present_empty(present, phrase):
    facts = boundary.program_facts(
        changed_evidence(lambda p: p["field_records"][-1].update(present=present, display_value=""))
    )
    report = boundary.render_group(
        {
            "case_id": "fixture",
            "facts": facts,
            "source_check": {"saved_exact_reextraction_verified": False},
        },
        [],
    )
    assert phrase in report
    assert ("存在且显示为空" in report) is present


def test_duplicate_reference_and_wrong_occurrence_are_rejected():
    duplicate = changed_evidence(lambda p: p["field_records"].append(p["field_records"][-1]))
    with pytest.raises(ValueError, match="Duplicate"):
        boundary.program_facts(duplicate)
    wrong = changed_evidence(lambda p: p["field_records"][-1].update(occurrence=8))
    with pytest.raises(ValueError, match="locator"):
        boundary.program_facts(wrong)


@pytest.mark.parametrize("where", ["payload", "item", "error"])
def test_incomplete_evidence_is_excluded_and_cannot_support_references(where):
    evidence = (
        changed_evidence(lambda p: p.update(truncated=True))
        if where == "payload"
        else fixture_evidence()
    )
    if where != "payload":
        evidence[1]["truncated" if where == "item" else "error"] = True
    facts = boundary.program_facts(evidence)
    assert facts["usable_field_references"] == []
    assert not facts["required_user_agent_predicates_complete"]
    result = boundary.gate(facts, {"saved_exact_reextraction_verified": False}, TEXT, decision())
    assert not result["model_body_included"]


@pytest.mark.parametrize(
    "corruption", ["count", "missing", "duplicate", "capture", "boolean", "status"]
)
def test_saved_certificate_requires_exact_unique_coverage_and_typed_counts(corruption):
    facts = boundary.program_facts(fixture_evidence())
    certificate = proof(facts)
    if corruption == "count":
        certificate["matched_count"] = 999
    elif corruption == "missing":
        certificate["records"].pop()
    elif corruption == "duplicate":
        certificate["records"][-1] = certificate["records"][0]
    elif corruption == "capture":
        certificate["capture_sha256"] = "b" * 64
    elif corruption == "boolean":
        certificate["record_count"] = True
    else:
        certificate["records"][0]["status"] = "field_record_mismatch"
    capture = next(iter(facts["capture_sha256_by_evidence"].values()))
    check = boundary.source_check(certificate, facts, capture)
    assert not check["saved_exact_reextraction_verified"]
    assert check["matched_unique_field_records"] == 0
    assert not boundary.gate(facts, check, TEXT, decision())["model_body_included"]


@pytest.mark.parametrize(
    "kind,value", [("human", "pending"), ("human", "rejected"), ("assistant", "approved")]
)
def test_review_decision_and_kind_gate_not_inferred_from_format(kind, value):
    facts = boundary.program_facts(fixture_evidence())
    result = boundary.gate(
        facts, {"saved_exact_reextraction_verified": True}, TEXT, decision(kind, value)
    )
    assert not result["model_body_included"]


@pytest.mark.parametrize(
    "mutation", ["unknown_ref", "no_basis", "blank_limits", "duplicate_keys", "fenced"]
)
def test_declared_human_approval_does_not_bypass_technical_prerequisites(mutation):
    data = json.loads(TEXT)
    if mutation in {"unknown_ref", "no_basis"}:
        data["hypotheses"] = [
            {
                "text": "未证实的解释",
                "basis": ["E999/F9:http.user_agent/0"] if mutation == "unknown_ref" else [],
            }
        ]
    elif mutation == "blank_limits":
        data["limitations"] = [" "]
    text = json.dumps(data, ensure_ascii=False)
    if mutation == "duplicate_keys":
        text = text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    elif mutation == "fenced":
        text = "```json\n" + text + "\n```"
    facts = boundary.program_facts(fixture_evidence())
    result = boundary.gate(facts, {"saved_exact_reextraction_verified": True}, text, decision())
    assert not result["model_body_included"]


@pytest.mark.parametrize(
    "binding",
    ["response_sha256", "request_sha256", "evidence_sha256", "source_verification_sha256"],
)
def test_review_is_bound_to_response_request_evidence_and_certificate(study, binding):
    expected = boundary.template(boundary.load_study(study))
    review = deepcopy(expected)
    review["trials"][0]["binding"][binding] = "0" * 64
    with pytest.raises(ValueError, match="binding differs"):
        boundary.validate_review(review, expected)


def test_review_rejects_wrong_study_duplicate_trial_and_undeclared_completed_review(study):
    expected = boundary.template(boundary.load_study(study))
    review = deepcopy(expected)
    review["study_binding"]["protocol_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="different study"):
        boundary.validate_review(review, expected)
    review = deepcopy(expected)
    review["trials"].append(deepcopy(review["trials"][0]))
    with pytest.raises(ValueError, match="exactly once"):
        boundary.validate_review(review, expected)
    review = deepcopy(expected)
    review["trials"][0].update(decision="approved")
    with pytest.raises(ValueError, match="declared reviewer"):
        boundary.validate_review(review, expected)


def test_declared_review_includes_prose_without_promoting_it_to_verified_fact(study, tmp_path):
    expected = boundary.template(boundary.load_study(study))
    expected["trials"][0].update(decision())
    review = tmp_path / "manual-fixture-review.json"
    boundary.write_json(review, expected)
    result = boundary.publish(study, tmp_path / "with-review", review_path=review)
    assert result["totals"]["model_bodies_included"] == 1
    assert not result["trials"][0]["semantic_truth_automatically_verified"]
    assert "身份、独立性" in (tmp_path / "with-review/group-001/report.md").read_text(
        encoding="utf-8"
    )
    original = boundary.program_facts(boundary.read_json(study / "group-001/evidence.json"))
    assert boundary.read_json(tmp_path / "with-review/group-001/program-facts.json") == original


def test_legacy_import_carries_only_rejections_never_approvals(study, tmp_path):
    loaded = boundary.load_study(study)
    template = boundary.template(loaded)
    legacy = tmp_path / "legacy.json"
    data = {
        "trials": [
            {
                "id": row["id"],
                "response_sha256": row["binding"]["response_sha256"],
                "decision": "pending",
                "labels": [],
                "reviewer": "old reviewer",
            }
            for row in template["trials"]
        ]
    }
    data["trials"][0]["decision"] = "approved"
    boundary.write_json(legacy, data)
    assert boundary.import_legacy_rejections(loaded, legacy)["trials"][0]["decision"] == "pending"
    data["trials"][0].update(decision="rejected", labels=["source_confusion"], note="源混淆")
    boundary.write_json(legacy, data)
    result = boundary.import_legacy_rejections(loaded, legacy)
    assert result["trials"][0]["decision"] == "rejected"
    assert result["trials"][0]["reviewer_kind"] == "legacy_unverified"


def test_tampered_or_unsealed_evidence_is_not_publishable(study, tmp_path):
    path = study / "group-001/evidence.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact changed"):
        boundary.publish(study, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_missing_seal_entry_is_rejected_even_when_original_replay_matches(study):
    inventory = boundary.read_json(study / "artifact-sha256.json")
    del inventory["group-001/evidence.json"]
    boundary.write_json(study / "artifact-sha256.json", inventory)
    assert validation.replay(study)
    with pytest.raises(ValueError, match="absent from"):
        boundary.load_study(study)


def test_no_output_overwrite_or_write_inside_original_study(study, tmp_path):
    with pytest.raises(ValueError, match="outside"):
        boundary.publish(study, study / "report")
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "original.txt"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        boundary.publish(study, output)
    assert marker.read_text() == "keep"


@pytest.mark.parametrize("path", ["../escape", "/absolute", "D:/other", "x\\y", "x/../y"])
def test_artifact_paths_are_confined(tmp_path, path):
    # A rooted path without a drive reaches the containment check on Windows;
    # POSIX rejects it in the lexical check. Both must reject the path.
    with pytest.raises(ValueError):
        boundary.inside(tmp_path, path)


def test_symlink_artifacts_are_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_text("data")
    try:
        (tmp_path / "link").symlink_to(target)
    except OSError:
        pytest.skip("This OS account cannot create symlinks.")
    with pytest.raises(ValueError, match="Symlink"):
        boundary.inside(tmp_path, "link")


def test_quote_round_trips_dangerous_markup_and_direction_controls():
    text = "`<script>&</script> [link](https://example.com)\n\u202e"
    rendered = boundary.quoted(text)
    assert json.loads(rendered[1:-1]) == text
    assert rendered.count("`") == 2 and "<script>" not in rendered and "\u202e" not in rendered


def test_keywords_are_not_an_automatic_semantic_judge():
    # Two conflicting sentences have the same structural gate result before human review.
    facts = boundary.program_facts(fixture_evidence())
    for sentence in ("远端服务器的编码没有证据。", "远端服务器确定插入了所有中点。"):
        text = json.dumps({"schema_version": 1, "hypotheses": [], "limitations": [sentence]})
        result = boundary.gate(
            facts, {"saved_exact_reextraction_verified": True}, text, decision("none", "pending")
        )
        assert result["blocking_reasons"] == ["review_pending"]
        assert not result["semantic_truth_automatically_verified"]


def test_certificate_for_different_payload_capture_never_verifies():
    facts = boundary.program_facts(fixture_evidence())
    certificate = proof(facts, "a" * 64)
    assert not boundary.source_check(certificate, facts, "a" * 64)[
        "saved_exact_reextraction_verified"
    ]


def test_installer_is_additive_idempotent_and_refuses_conflicts(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "boundary_installer", ROOT / "report-boundary/apply_update.py"
    )
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    project, package = tmp_path / "project", tmp_path / "update"
    (project / "src/pcap_mcp").mkdir(parents=True)
    core = project / "src/pcap_mcp/old.py"
    core.write_bytes(b"byte-frozen\n")
    (package / "payload/report-boundary").mkdir(parents=True)
    for name in ("one.txt", "two.txt"):
        (package / "payload/report-boundary" / name).write_bytes(b"new\n")
    manifest = {
        "version": boundary.VERSION,
        "base_sha256": {"src/pcap_mcp/old.py": installer.digest(core)},
        "files": [
            {
                "path": "report-boundary/" + name,
                "sha256_normalized": installer.digest(
                    package / "payload/report-boundary" / name, normalized=True
                ),
            }
            for name in ("one.txt", "two.txt")
        ],
    }
    boundary.write_json(package / "update-manifest.json", manifest)
    installer.apply(project, package, check=True)
    assert not (project / "report-boundary").exists()
    (project / "report-boundary").mkdir()
    (project / "report-boundary/two.txt").write_bytes(b"user addition")
    with pytest.raises(ValueError, match="Existing addition differs"):
        installer.apply(project, package)
    assert not (project / "report-boundary/one.txt").exists()
    (project / "report-boundary/two.txt").unlink()
    installer.apply(project, package)
    installer.apply(project, package)
    assert core.read_bytes() == b"byte-frozen\n"
    (project / "src/pcap_mcp/extra.py").write_bytes(b"additional module\n")
    with pytest.raises(ValueError, match="inventory differs"):
        installer.apply(project, package)


def test_update_payload_cannot_modify_frozen_core(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "boundary_installer_paths", ROOT / "report-boundary/apply_update.py"
    )
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    with pytest.raises(ValueError, match="Unsafe"):
        installer.safe(tmp_path, "src/pcap_mcp/validation.py")
