"""Presentation controls and local checkpoints; no LLM or packet parsing dependencies."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

from .evidence_io import parse_tool_payload

REQUIRED_UA_PROPERTIES = (
    "present",
    "display_value",
    "injection_kinds",
    "transformations.unicode_controls_removed",
    "transformations.middle_dots_inserted_by_server",
    "transformations.middle_dots_in_decoded_source",
)
MAX_AUDIT_RESPONSE_CHARS = 50_000


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def flatten_record(record: dict[str, Any]) -> dict[str, Any]:
    """Keep every leaf and list; flatten only the controlled nested metadata keys."""
    flattened: dict[str, Any] = {}

    def walk(data: dict[str, Any], prefix: str = "") -> None:
        for key, value in data.items():
            if "." in key:
                raise ValueError("Unexpected dotted record key.")
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict) and value:
                walk(value, path)
            else:
                flattened[path] = deepcopy(value)

    walk(record)
    return flattened


def expand_record(record: dict[str, Any]) -> dict[str, Any]:
    """Inverse used to test information preservation, never to fabricate evidence."""
    expanded: dict[str, Any] = {}
    for path, value in record.items():
        parts = path.split(".")
        target = expanded
        for key in parts[:-1]:
            target = target.setdefault(key, {})
            if not isinstance(target, dict):
                raise ValueError("Conflicting flattened record paths.")
        if parts[-1] in target:
            raise ValueError("Duplicate flattened record path.")
        target[parts[-1]] = deepcopy(value)
    return expanded


def model_view(text: str, view: str) -> str:
    if view not in {"structured", "flat"}:
        raise ValueError("Unknown evidence view.")
    payload = parse_tool_payload(text)
    if view == "structured" or not payload or payload.get("schema") != "pcap-mcp.http-fields/v1":
        return text
    projected = deepcopy(payload)
    projected["field_records"] = [flatten_record(record) for record in payload["field_records"]]
    body = json.dumps(projected, ensure_ascii=False, indent=2)
    body = body.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    # Reuse the exact trust/provenance header. Only nested metadata representation changes.
    marker = '\">\n'
    prefix, sep, _ = text.partition(marker)
    if not sep:
        raise ValueError("Field evidence has no protected envelope.")
    return prefix + sep + body + "\n</untrusted_pcap_data>"


def predicate_statistics(
    checked: dict[str, Any], registry: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    required = {
        (reference, prop)
        for reference, record in registry.items()
        if record["field"] == "http.user_agent"
        for prop in REQUIRED_UA_PROPERTIES
    }
    accepted = [fact for fact in checked["facts"] if fact["accepted"]]
    covered = {(fact["record"], fact["property"]) for fact in accepted} & required
    return {
        "proposed_facts": len(checked["facts"]),
        "accepted_facts": len(accepted),
        "rejected_facts": len(checked["facts"]) - len(accepted),
        "required_user_agent_predicates": len(required),
        "covered_user_agent_predicates": len(covered),
        "user_agent_predicate_coverage": len(covered) / len(required) if required else None,
        "all_required_user_agent_predicates_covered": bool(required) and covered == required,
        "scope": "enumerated_user_agent_record_properties_not_semantic_task_correctness",
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8"))
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class ResearchAudit:
    """Write protected evidence immediately, including when final reporting fails."""

    def __init__(
        self,
        evidence_path: Path | None = None,
        audit_path: Path | None = None,
        *,
        sanitize: Callable[[str], str] = lambda text: text,
    ) -> None:
        self.evidence_path = evidence_path
        self.audit_path = audit_path
        self.sanitize = sanitize
        self.data: dict[str, Any] = {
            "schema_version": 1,
            "status": "started",
            "model_rounds": 0,
            "responses": [],
            "evidence_views": [],
            "response_storage": "locally_redacted_copy_not_verbatim_original",
        }

    def flush(self) -> None:
        if self.audit_path:
            write_json_atomic(self.audit_path, self.data)

    def evidence(self, evidence: list[dict[str, Any]], view: str) -> None:
        if self.evidence_path:
            write_json_atomic(self.evidence_path, evidence)
        views = []
        for item in evidence:
            payload = parse_tool_payload(item["result"])
            if payload and payload.get("schema") == "pcap-mcp.http-fields/v1":
                rendered = model_view(item["result"], view)
                views.append({
                    "evidence_id": item["id"],
                    "view": view,
                    "canonical_payload_sha256": canonical_digest(payload),
                    "model_view_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                    "model_view_characters": len(rendered),
                })
        self.data["evidence_views"] = views
        self.flush()

    def response(self, number: int, phase: str, response: Any) -> None:
        self.data["model_rounds"] = number
        message = response.choices[0].message if response.choices else None
        text = (message.content or "") if message else ""
        protected = self.sanitize(text)
        usage = getattr(response, "usage", None)
        self.data["responses"].append({
            "round": number,
            "phase": phase,
            "original_response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "original_characters": len(text),
            "text": protected[:MAX_AUDIT_RESPONSE_CHARS],
            "stored_copy_truncated": len(protected) > MAX_AUDIT_RESPONSE_CHARS,
            "format_valid": None,
            "usage": usage.model_dump() if hasattr(usage, "model_dump") else None,
        })
        self.flush()

    def format_result(self, number: int, valid: bool, reason: str | None = None) -> None:
        for response in reversed(self.data["responses"]):
            if response["round"] == number:
                response["format_valid"] = valid
                response["format_error"] = reason
                break
        attempts = [
            response
            for response in self.data["responses"]
            if response["format_valid"] is not None
        ]
        self.data["format_first_pass_valid"] = attempts[0]["format_valid"] if attempts else None
        self.data["format_attempts"] = len(attempts)
        self.data["format_repair_requests"] = sum(
            response["phase"] == "format_repair" for response in self.data["responses"]
        )
        self.flush()

    def finish(self, status: str, error: str | None = None) -> None:
        self.data["status"] = status
        self.data["error_type"] = error
        self.flush()
