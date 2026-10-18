"""Offline publication boundary around the byte-frozen v3 study, with no model calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

# Direct execution works in the user's existing project environment.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pcap_mcp import frozen_prose, validation
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.reporting import decode_prose, generate_report
from pcap_mcp.research import REQUIRED_UA_PROPERTIES

VERSION = "report-boundary-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
COUNT_LABELS = {
    "transformations.unicode_controls_removed": "分析程序移除的 Unicode 控制字符计数",
    "transformations.middle_dots_inserted_by_server": "分析程序插入的中点计数",
    "transformations.middle_dots_in_decoded_source": "解码后来源文本中的中点计数",
    "input_decoding.tshark_display_replacement_characters": "上游 tshark 展示替换字符计数",
}
ORIGIN_LABELS = {
    "none": "两个中点计数均为零。",
    "analysis_program": "中点计数仅记录了分析程序插入。",
    "decoded_source": "中点计数仅记录了解码后来源文本中的中点。",
    "both": "有效计数分别记录了分析程序插入和解码来源中点。",
    "unknown": "中点来源计数不完整或类型无效，来源保留未知。",
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path) -> Any:
    if path.stat().st_size > 2_000_000:
        raise ValueError("JSON artifact exceeds the offline reader limit.")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result

    def reject(value):
        raise ValueError("Non-finite JSON constant: " + value)

    return json.loads(
        path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique, parse_constant=reject
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )


def inside(root: Path, relative: str) -> Path:
    """Reject path traversal and symlinks before either reading or writing."""
    part = Path(relative)
    if (
        not isinstance(relative, str)
        or "\\" in relative
        or ":" in relative
        or part.is_absolute()
        or not part.parts
        or any(p in {".", ".."} for p in relative.split("/"))
    ):
        raise ValueError("Unsafe artifact path.")
    target = root / part
    for candidate in (target, *target.parents):
        if candidate == root.parent:
            break
        if candidate.is_symlink():
            raise ValueError("Symlink in artifact path.")
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact escapes its root.")
    return target


def quoted(value: Any) -> str:
    """Data is rendered as a JSON literal, never executable Markdown or HTML."""
    result = json.dumps(value, ensure_ascii=False, allow_nan=False)
    for char in ("`", "<", ">", "&"):
        result = result.replace(char, "\\u" + format(ord(char), "04x"))
    result = "".join(
        json.dumps(char, ensure_ascii=True)[1:-1]
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
        else char
        for char in result
    )
    return "`" + result + "`"


def program_facts(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    closed = generate_report(evidence)
    records = {}
    captures = {}
    for item in evidence:
        if item["id"] not in closed["source_payload_sha256"]:
            continue
        payload = parse_tool_payload(item["result"])
        if payload is None:
            raise ValueError("Accepted field envelope cannot be decoded.")
        captures[item["id"]] = payload.get("capture_sha256")
        for row in payload["field_records"]:
            records[item["id"] + "/" + row["record_id"]] = row
    ua = []
    for reference, record in sorted(records.items()):
        if record["field"] != "http.user_agent":
            continue
        facts = {f["property"]: f["value"] for f in closed["facts"] if f["record"] == reference}
        missing = [p for p in REQUIRED_UA_PROPERTIES if p not in facts]
        ua.append(
            {
                "reference": reference,
                "facts": facts,
                "limited_source_labels": {
                    a["property"]: a["value"]
                    for a in closed["attributions"]
                    if a["record"] == reference
                },
                "dissector_creator": record.get("dissector_creator"),
                "missing_required_properties": sorted(missing),
            }
        )
    return {
        "schema_version": VERSION,
        "producer": "program_from_typed_saved_records_no_model",
        "closed": {key: closed[key] for key in frozen_prose.CLOSED_KEYS},
        "usable_field_references": sorted(records),
        "capture_sha256_by_evidence": captures,
        "user_agent_records": ua,
        "required_user_agent_predicates_complete": bool(ua)
        and all(not row["missing_required_properties"] for row in ua),
        "finite_limitations": [
            {"id": "encoding", "text": "显式解码方式不能证明原字符编码。"},
            {"id": "semantics", "text": "字段值、启发式匹配和转换计数不能证明意图或攻击成功。"},
            {"id": "coverage", "text": "记录仅覆盖已导出的字段 occurrence，不能推出整包调查完整。"},
            {
                "id": "position",
                "text": "中点来源计数区分来源总数，不提供每个中点的原始字节位置。",
            },
        ],
    }


def source_check(
    proof: dict[str, Any], facts: dict[str, Any], capture_sha256: str
) -> dict[str, Any]:
    """Validate the saved re-extraction certificate, without re-running tshark."""
    expected = set(facts["usable_field_references"])
    rows = proof.get("records", [])
    valid_rows = isinstance(rows, list) and all(isinstance(r, dict) for r in rows)
    refs = [r.get("reference") for r in rows] if valid_rows else []
    valid = (
        bool(expected)
        and type(proof.get("schema_version")) is int
        and proof["schema_version"] == 1
        and proof.get("coverage") == "only_exported_field_occurrences_not_entire_capture"
        and proof.get("scope") == "decoded_http_fields_and_transformations_not_intent_or_success"
        and bool(facts["capture_sha256_by_evidence"])
        and all(v == capture_sha256 for v in facts["capture_sha256_by_evidence"].values())
        and valid_rows
        and all(isinstance(r, str) for r in refs)
        and len(refs) == len(set(refs))
        and set(refs) == expected
        and proof.get("capture_sha256") == capture_sha256
        and proof.get("capture_unchanged_during_verification") is True
        and proof.get("all_records_match") is True
        and type(proof.get("record_count")) is int
        and type(proof.get("matched_count")) is int
        and proof["record_count"] == proof["matched_count"] == len(expected)
        and all(r.get("matched") is True and r.get("status") == "matched" for r in rows)
    )
    return {
        "saved_exact_reextraction_verified": bool(valid),
        "matched_unique_field_records": len(expected) if valid else 0,
        "scope": "saved_certificate_replayed_not_new_live_reextraction_or_semantic_truth",
    }


def load_study(root: Path) -> dict[str, Any]:
    root = root.resolve()
    inventory = read_json(inside(root, "artifact-sha256.json"))
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError("A sealed completed v3 study is required.")
    for relative, expected in inventory.items():
        path = inside(root, relative)
        if not isinstance(expected, str) or not SHA.fullmatch(expected) or sha(path) != expected:
            raise ValueError("Saved artifact changed: " + relative)
    protocol = read_json(inside(root, "protocol.json"))
    for group in protocol["groups"]:
        inside(root, group["id"])
        for arm in group["arms"]:
            inside(root, group["id"] + "/" + arm)
    required = {"protocol.json", "protocol.sha256"}
    for case in protocol["cases"]:
        required.add(case["capture"])
        inside(root, case["capture"])
    for group in protocol["groups"]:
        required.update({group["id"] + "/evidence.json", group["id"] + "/source-verification.json"})
        for arm in group["arms"]:
            prefix = group["id"] + "/" + arm
            required.add(prefix + "/status.json")
            if inside(root, prefix + "/response.txt").exists():
                required.update({prefix + "/response.txt", prefix + "/request.json"})
    if not required.issubset(inventory):
        raise ValueError("Required inputs are absent from the artifact inventory.")
    replayed = validation.replay(root)  # Original implementation, unchanged; no API calls.
    groups = []
    for group in protocol["groups"]:
        case = next(c for c in protocol["cases"] if c["id"] == group["case_id"])
        evidence = read_json(inside(root, group["id"] + "/evidence.json"))
        facts = program_facts(evidence)
        proof = read_json(inside(root, group["id"] + "/source-verification.json"))
        groups.append(
            {
                "id": group["id"],
                "case_id": group["case_id"],
                "evidence": evidence,
                "facts": facts,
                "source_check": source_check(proof, facts, case["capture_sha256"]),
            }
        )
    return {
        "root": root,
        "protocol": protocol,
        "replayed": replayed,
        "groups": groups,
        "study_binding": {
            "protocol_sha256": sha(root / "protocol.json"),
            "artifact_inventory_sha256": sha(root / "artifact-sha256.json"),
            "boundary_code_sha256": sha(Path(__file__)),
        },
        "input_sha256": {
            **inventory,
            "artifact-sha256.json": sha(root / "artifact-sha256.json"),
            "summary.json": sha(root / "summary.json"),
        },
    }


def template(study: dict[str, Any]) -> dict[str, Any]:
    root = study["root"]
    trials = []
    for trial in study["replayed"]["trials"]:
        prefix = trial["id"]
        group = prefix.split("/")[0]
        trials.append(
            {
                "id": prefix,
                "binding": {
                    name: sha(root / relative) if (root / relative).is_file() else None
                    for name, relative in (
                        ("response_sha256", prefix + "/response.txt"),
                        ("request_sha256", prefix + "/request.json"),
                        ("evidence_sha256", group + "/evidence.json"),
                        ("source_verification_sha256", group + "/source-verification.json"),
                    )
                },
                "decision": "pending",
                "reviewer_kind": "none",
                "reviewer": "",
                "labels": [],
                "note": "",
            }
        )
    return {
        "schema_version": VERSION,
        "study_binding": study["study_binding"],
        "instruction": "逐条核对事实、来源、计数、引用与限制。人工审阅时自行填写 "
        "reviewer_kind=human、reviewer 和 note；approved 且无错误标签才具备正文纳入资格。"
        "这是声明的审阅身份，不是系统认证的独立人工评测。不要修改 binding。",
        "allowed_labels": list(validation.REVIEW_LABELS),
        "trials": trials,
    }


def validate_review(data: dict[str, Any], expected: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        data.get("schema_version") != VERSION
        or data.get("study_binding") != expected["study_binding"]
    ):
        raise ValueError("Review belongs to a different study or boundary implementation.")
    rows = data.get("trials")
    wanted = {r["id"]: r for r in expected["trials"]}
    if (
        not isinstance(rows, list)
        or not all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in rows)
        or len(rows) != len(wanted)
        or {r["id"] for r in rows} != set(wanted)
    ):
        raise ValueError("Review must cover every trial exactly once.")
    output = {}
    for row in rows:
        if row.get("binding") != wanted[row["id"]]["binding"]:
            raise ValueError("Review binding differs from saved response/evidence/request/proof.")
        decision, kind = row.get("decision"), row.get("reviewer_kind")
        labels = row.get("labels")
        if (
            decision not in {"pending", "approved", "rejected"}
            or kind not in {"none", "human", "assistant", "legacy_unverified"}
            or not isinstance(labels, list)
            or not all(isinstance(x, str) and x in validation.REVIEW_LABELS for x in labels)
            or len(labels) != len(set(labels))
            or any(not isinstance(row.get(key), str) for key in ("reviewer", "note"))
        ):
            raise ValueError("Invalid review decision, reviewer or labels.")
        if decision != "pending" and (
            kind == "none" or not row["reviewer"].strip() or not row["note"].strip()
        ):
            raise ValueError("Completed reviews need a declared reviewer kind, name and note.")
        if decision == "approved" and (labels or not row["binding"]["response_sha256"]):
            raise ValueError("Cannot approve missing responses or responses with error labels.")
        output[row["id"]] = row
    return output


def import_legacy_rejections(study: dict[str, Any], legacy_path: Path) -> dict[str, Any]:
    """Only carry forward SHA-bound rejections. Never promote old approvals."""
    validation.review(study["root"], legacy_path)
    legacy = read_json(legacy_path)
    result = template(study)
    old = {r["id"]: r for r in legacy["trials"]}
    for row in result["trials"]:
        previous = old[row["id"]]
        if previous["decision"] == "rejected":
            row.update(
                decision="rejected",
                reviewer_kind="legacy_unverified",
                reviewer="legacy_import:" + previous["reviewer"],
                labels=previous["labels"],
                note=previous.get("note", "").strip() or "旧版 SHA 绑定审阅拒绝。",
            )
    result["import_scope"] = "legacy_rejections_only_identity_not_authenticated"
    return result


def gate(
    facts: dict[str, Any], source: dict[str, Any], text: str | None, review: dict[str, Any]
) -> dict[str, Any]:
    # Parsing uses only the previously accepted saved-field references.
    prose = None
    problems = []
    if text is None:
        problems.append("missing_response")
    else:
        try:
            prose = decode_prose(text)
        except (ValueError, TypeError, OverflowError, RecursionError):
            problems.append("invalid_structure")
        if prose:
            refs = set(facts["usable_field_references"])
            if any(not h["basis"] or set(h["basis"]) - refs for h in prose["hypotheses"]):
                problems.append("invalid_or_empty_hypothesis_basis")
            if not any(s.strip() for s in prose["limitations"]):
                problems.append("missing_nonempty_limitations")
            if any(not h["text"].strip() for h in prose["hypotheses"]):
                problems.append("empty_hypothesis_text")
            sentences = [h["text"] for h in prose["hypotheses"]] + prose["limitations"]
            if not re.search(r"[\u4e00-\u9fff]", "".join(sentences)):
                problems.append("missing_chinese_prose")
    if not facts["required_user_agent_predicates_complete"]:
        problems.append("incomplete_user_agent_predicates")
    if not source["saved_exact_reextraction_verified"]:
        problems.append("saved_source_not_exactly_verified")
    if review["decision"] != "approved":
        problems.append("review_" + review["decision"])
    elif review["reviewer_kind"] != "human":
        problems.append("approval_not_declared_human_review")
    return {
        "model_body_included": not problems,
        "blocking_reasons": problems,
        "review": review,
        "included_model_prose": prose if not problems else None,
        "semantic_truth_automatically_verified": False,
        "review_identity_scope": "declared_in_file_not_authenticated_or_independence_verified",
    }


def render_group(group: dict[str, Any], trials: list[dict[str, Any]]) -> str:
    facts, source = group["facts"], group["source_check"]
    lines = [
        "# 字段事实报告：" + quoted(group["case_id"]),
        "",
        "来源与转换说明由程序按已保存字段记录生成；模型正文另经审阅门槛。",
        "",
        "分析程序指 pcap-mcp。远端 HTTP 服务器、解码来源文本与上游 tshark 展示层分别记录。",
        "",
        "已保存的精确重提取校验："
        + ("通过。" if source["saved_exact_reextraction_verified"] else "未通过。"),
        "本次仅重算保存记录和校验凭据，未重新运行 tshark。",
        "",
    ]
    for row in facts["user_agent_records"]:
        f = row["facts"]
        lines += ["## User-Agent " + quoted(row["reference"]), ""]
        present = f.get("present")
        lines.append(
            "该 occurrence 的字段存在性："
            + (
                "存在。"
                if present is True
                else "未出现。"
                if present is False
                else "未知（缺失或类型无效）。"
            )
        )
        if "display_value" in f:
            lines.append("解码和转换后的显示值：" + quoted(f["display_value"]) + "。")
        else:
            lines.append("显示值不可用；不能视作空字符串。")
        if present is True and f.get("display_value") == "":
            lines.append("该字段存在且显示为空，不能视作字段缺失。")
        if "injection_kinds" in f:
            lines.append("启发式匹配标签：" + quoted(f["injection_kinds"]) + "。")
        else:
            lines.append("启发式匹配标签不可用；不能视作未匹配。")
        lines.append("记录中的解码依据：" + quoted(f.get("value_basis", "不可用")) + "。")
        lines.append("记录中的解码器版本：" + quoted(row["dissector_creator"]) + "。")
        removed = f.get("input_decoding.header_envelope_removed")
        lines.append(
            "解码时移除 HTTP 头包络："
            + ("是。" if removed is True else "否。" if removed is False else "未知。")
        )
        for prop, label in COUNT_LABELS.items():
            count = str(f[prop]) if prop in f else "未知（缺失或类型无效）"
            lines.append(label + "：" + count + "。")
        origin = row["limited_source_labels"].get("middle_dot_origin", "unknown")
        lines.append(ORIGIN_LABELS[origin])
        if "transformations.unicode_controls_removed" in f:
            lines.append(
                "有效计数为零，本分析程序没有记录控制字符移除。"
                if f["transformations.unicode_controls_removed"] == 0
                else "有效计数记录了本分析程序的控制字符移除。"
            )
        lines.append("中点插入与控制字符移除是分别记录的操作，不能把插入计数改写成字符替换计数。")
        lines.append("tshark 展示替换计数单独描述上游展示层，不是原始控制字符数量。")
        lines.append("")
    if not facts["user_agent_records"]:
        lines += ["没有可用 User-Agent 记录，不能视作调查成功。", ""]
    if facts["closed"]["excluded_evidence"]:
        lines += [
            "未用于字段事实的证据：" + quoted(facts["closed"]["excluded_evidence"]) + "。",
            "",
        ]
    lines += ["## 程序生成的有限限制", ""]
    lines.extend("- " + item["text"] for item in facts["finite_limitations"])
    lines += ["", "## 模型正文纳入状态", ""]
    for row in trials:
        lines += ["### " + quoted(row["id"]), ""]
        if not row["model_body_included"]:
            lines += ["正文未纳入。原因：" + quoted(row["blocking_reasons"]) + "。", ""]
            continue
        lines += [
            "审阅文件声明已由人工逐条审阅；系统未认证审阅者身份、独立性或任意语义真实性。",
            "纳入的是模型的推测和限制，不加入程序事实区。",
            "",
        ]
        prose = row["included_model_prose"]
        lines.extend(
            "- 推测：" + quoted(h["text"]) + "；依据：" + quoted(h["basis"])
            for h in prose["hypotheses"]
        )
        lines.extend("- 限制：" + quoted(s) for s in prose["limitations"])
        lines.append("")
    return "\n".join(lines) + "\n"


def publish(
    root: Path,
    output: Path,
    *,
    review_path: Path | None = None,
    legacy_rejections: Path | None = None,
) -> dict[str, Any]:
    if review_path and legacy_rejections:
        raise ValueError("Choose one review input.")
    root, output = root.resolve(), output.resolve()
    if output == root or output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError("Output must be outside the original study tree.")
    if output.exists():
        raise ValueError("Output already exists; choose a new result directory.")
    study = load_study(root)
    expected = template(study)
    applied = (
        read_json(review_path)
        if review_path
        else (import_legacy_rejections(study, legacy_rejections) if legacy_rejections else expected)
    )
    reviews = validate_review(applied, expected)
    supplied_review = review_path or legacy_rejections
    review_bytes = supplied_review.read_bytes() if supplied_review else None
    trial_rows = []
    for trial in study["replayed"]["trials"]:
        path = root / trial["id"] / "response.txt"
        text = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        group = next(g for g in study["groups"] if g["id"] == trial["id"].split("/")[0])
        result = gate(group["facts"], group["source_check"], text, reviews[trial["id"]])
        if trial["status"] != "completed":
            result["blocking_reasons"].append("trial_not_completed")
            result.update(model_body_included=False, included_model_prose=None)
        trial_rows.append({"id": trial["id"], **result})
    included = sum(row["model_body_included"] for row in trial_rows)
    result = {
        "schema_version": VERSION,
        "study_binding": study["study_binding"],
        "totals": {
            "shared_groups": len(study["groups"]),
            "planned_model_bodies": len(trial_rows),
            "model_bodies_included": included,
            "model_bodies_withheld": len(trial_rows) - included,
            "groups_with_complete_user_agent_predicates": sum(
                g["facts"]["required_user_agent_predicates_complete"] for g in study["groups"]
            ),
            "saved_source_matched_unique_field_records": sum(
                g["source_check"]["matched_unique_field_records"] for g in study["groups"]
            ),
            "new_model_requests": 0,
        },
        "review_counts": {
            kind: sum(r["decision"] == kind for r in reviews.values())
            for kind in ("pending", "approved", "rejected")
        },
        "trials": trial_rows,
        "semantic_scope": "explicit_review_decisions_not_automatic_semantic_accuracy",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".report-boundary-", dir=output.parent))
    try:
        write_json(temporary / "review-template.json", expected)
        write_json(temporary / "review-applied.json", applied)
        if review_bytes is not None:
            (temporary / "review-input-original.json").write_bytes(review_bytes)
        write_json(temporary / "publication.json", result)
        write_json(temporary / "input-sha256.json", study["input_sha256"])
        for group in study["groups"]:
            folder = temporary / group["id"]
            folder.mkdir()
            write_json(folder / "program-facts.json", group["facts"])
            write_json(folder / "source-check.json", group["source_check"])
            rows = [r for r in trial_rows if r["id"].split("/")[0] == group["id"]]
            (folder / "report.md").write_text(render_group(group, rows), encoding="utf-8")
        for row in trial_rows:
            folder = temporary / "review-only" / row["id"]
            folder.mkdir(parents=True)
            source = root / row["id"] / "response.txt"
            if source.is_file():
                shutil.copyfile(source, folder / "response-original.txt")
            write_json(
                folder / "review-status.json",
                {k: v for k, v in row.items() if k != "included_model_prose"},
            )
        (temporary / "README.txt").write_text(
            "先读 group-*/report.md。review-only/ 保存原始模型输出，不属于报告正文。\n"
            "publication.json 记录每条纳入门槛；review-template.json 供逐条语义审阅。\n"
            "本操作不调用模型、不重提取抓包、不修改原 v3 实验。\n",
            encoding="utf-8",
        )
        # Catch edits made while building, before exposing a completed result.
        for relative, expected_sha in study["input_sha256"].items():
            if sha(inside(root, relative)) != expected_sha:
                raise ValueError("Study changed while generating the report: " + relative)
        write_json(
            temporary / "artifact-sha256.json",
            {
                p.relative_to(temporary).as_posix(): sha(p)
                for p in sorted(temporary.rglob("*"))
                if p.is_file()
            },
        )
        temporary.rename(output)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--review-json", type=Path)
    inputs.add_argument("--import-legacy-rejections", type=Path)
    args = parser.parse_args()
    try:
        result = publish(
            args.study,
            args.output,
            review_path=args.review_json,
            legacy_rejections=args.import_legacy_rejections,
        )
    except (ValueError, OSError, KeyError, TypeError, StopIteration) as exc:
        parser.exit(2, f"Report stopped: {exc}\n")
    print(json.dumps(result["totals"], ensure_ascii=False))
    print("Saved: " + str(args.output.resolve()))


if __name__ == "__main__":
    main()
