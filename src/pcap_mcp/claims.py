"""Check only explicitly enumerated field predicates, never arbitrary semantic truth."""

from __future__ import annotations

import json
import math
from typing import Any

from .evidence_io import parse_tool_payload
from .research import predicate_statistics

PROPERTIES = {
    "value_basis",
    "input_decoding.tshark_display_replacement_characters",
    "input_decoding.header_envelope_removed",
    "present",
    "display_value",
    "injection_kinds",
    "transformations.redaction_changed",
    "transformations.uri_suffix_removed",
    "transformations.unicode_controls_removed",
    "transformations.middle_dots_inserted_by_server",
    "transformations.middle_dots_in_decoded_source",
}
CLAIMS_PROMPT = """
Final answer MUST be a JSON object, with no markdown fences:
{"schema_version":1,"facts":[{"record":"E02/F4:http.user_agent/0",
"property":"transformations.unicode_controls_removed","value":0}],
"hypotheses":[{"text":"A cautious hypothesis, explicitly unverified",
"basis":["E02/F4:http.user_agent/0"]}],"limitations":["What is still unknown"]}.
Each fact is ONE exact field predicate, copied from an actual field_records item.
The record reference is evidence ID + '/' + record_id; do not invent IDs.
Allowed properties: value_basis, input_decoding.tshark_display_replacement_characters,
input_decoding.header_envelope_removed, present, display_value, injection_kinds,
transformations.redaction_changed, transformations.uri_suffix_removed,
transformations.unicode_controls_removed, transformations.middle_dots_inserted_by_server,
transformations.middle_dots_in_decoded_source.
Never put interpretation, intent, attack success or evasion into facts.
The summary E01 has no HTTP field records and cannot support any such predicate.
Use an empty facts list if no field records exist. Hypotheses are NOT verified facts.
For EACH User-Agent occurrence, including present=false, cover present, display_value,
injection_kinds, transformations.unicode_controls_removed,
transformations.middle_dots_inserted_by_server, transformations.middle_dots_in_decoded_source.
Do not substitute counters from another field. U+FFFD in the tshark display is not U+00B7
inserted by this program, and is not a count of original invisible characters.
All hypothesis and limitation prose must use the controller's report language.
"""


def field_registry(evidence: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for item in evidence:
        if item.get("error") or item.get("truncated"):
            continue
        payload = parse_tool_payload(item.get("result", ""))
        if not payload or payload.get("schema") != "pcap-mcp.http-fields/v1":
            continue
        for record in payload.get("field_records", []):
            ref = f"{item['id']}/{record['record_id']}"
            if ref in registry:
                raise ValueError("Duplicate field reference.")
            registry[ref] = record
    return registry


def parse_claims(text: str) -> dict[str, Any]:
    clean = text.strip()
    if clean.startswith("```json\n") and clean.endswith("\n```"):
        clean = clean[8:-4]
    if len(clean) > 50_000:
        raise ValueError("Claims exceeded the report character limit.")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key.")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("Non-finite JSON constants are not allowed.")

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite JSON numbers are not allowed.")
        return result

    data = json.loads(
        clean, object_pairs_hook=unique_object,
        parse_constant=reject_constant, parse_float=finite_float,
    )
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
    ):
        raise ValueError("Claims must have schema_version: 1.")
    if set(data) != {"schema_version", "facts", "hypotheses", "limitations"}:
        raise ValueError("Unexpected claims keys.")
    for key in ("facts", "hypotheses", "limitations"):
        if not isinstance(data[key], list) or len(data[key]) > 100:
            raise ValueError(f"{key} must be a list of at most 100 entries.")
    for fact in data["facts"]:
        if not isinstance(fact, dict) or set(fact) != {"record", "property", "value"}:
            raise ValueError("Each fact needs exactly record, property and value.")
        if not isinstance(fact["record"], str) or not isinstance(fact["property"], str):
            raise ValueError("Fact references and properties must be strings.")
    for hypothesis in data["hypotheses"]:
        if not isinstance(hypothesis, dict) or set(hypothesis) != {"text", "basis"}:
            raise ValueError("Each hypothesis needs exactly text and basis.")
        if not isinstance(hypothesis["text"], str) or len(hypothesis["text"]) > 4000:
            raise ValueError("Invalid hypothesis text.")
        if (
            not isinstance(hypothesis["basis"], list)
            or len(hypothesis["basis"]) > 100
            or any(not isinstance(ref, str) for ref in hypothesis["basis"])
        ):
            raise ValueError("Invalid hypothesis basis.")
    if any(not isinstance(x, str) or len(x) > 4000 for x in data["limitations"]):
        raise ValueError("Invalid limitation text.")
    return data


def check_claims(
    data: dict[str, Any],
    evidence: list[dict[str, Any]],
    verified_refs: set[str] | None = None,
) -> dict[str, Any]:
    registry = field_registry(evidence)
    results = []
    for index, fact in enumerate(data["facts"], 1):
        ref, prop = fact["record"], fact["property"]
        record = registry.get(ref)
        reason = "matches_record_only"
        if record is None:
            reason = "unknown_field_reference"
        elif prop not in PROPERTIES:
            reason = "unsupported_predicate"
        else:
            actual: Any = record
            for part in prop.split("."):
                actual = actual[part]
            # JSON types matter: bool False must not compare equal to numeric zero.
            if json.dumps(actual, sort_keys=True) != json.dumps(fact["value"], sort_keys=True):
                reason = "value_mismatch"
            elif verified_refs is not None:
                reason = (
                    "verified_field_predicate" if ref in verified_refs else "source_not_verified"
                )
        results.append(
            {
                "claim_id": f"C{index:02d}",
                **fact,
                "status": reason,
                "accepted": reason in {"matches_record_only", "verified_field_predicate"},
            }
        )
    invalid_basis = [ref for h in data["hypotheses"] for ref in h["basis"] if ref not in registry]
    checked = {
        "scope": "enumerated_field_predicates_not_arbitrary_semantic_truth",
        "facts": results,
        "hypotheses_are_unverified": True,
        "unknown_hypothesis_references": invalid_basis,
        "all_facts_accepted": bool(results) and all(x["accepted"] for x in results),
    }
    checked["statistics"] = predicate_statistics(checked, registry)
    return checked


def render_claims(data: dict[str, Any], checked: dict[str, Any]) -> str:
    lines = ["## 字段事实（仅与工具记录比较，原包重提取结果见 verification.json）", ""]
    for fact in checked["facts"]:
        if fact["accepted"]:
            value = json.dumps(fact["value"], ensure_ascii=False)
            # Render with JSON escaping and a code span, so a value cannot create headings.
            value = value.replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e")
            lines.append(
                f"- {fact['claim_id']}：`{fact['record']}` 的 "
                f"`{fact['property']}` = `{value}` [{fact['record'].split('/')[0]}]"
            )
        else:
            lines.append(f"- {fact['claim_id']}：未接受（{fact['status']}），不作为已支持事实。")
    if not checked["facts"]:
        lines.append("没有提出可检查的字段事实；不能据此声称分析正确。")
    lines.extend(["", "## 模型推测（未经语义核验）", ""])
    lines.extend(f"- {h['text']}" for h in data["hypotheses"])
    lines.extend(["", "## 局限", ""])
    lines.extend(f"- {text}" for text in data["limitations"])
    if checked["unknown_hypothesis_references"]:
        lines.append("⚠ 部分推测引用了不存在的字段证据。")
    lines.append("提示注入匹配是线索，不能单独证明意图、规避机制或攻击成功。")
    return "\n".join(lines)
