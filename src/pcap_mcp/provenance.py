"""HTTP decoded-field evidence. Never exports original unredacted field values."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .config import redaction_enabled
from .evidence_io import parse_tool_payload as parse_tool_payload
from .security import UNTRUSTED_HEADER, ZERO_WIDTH, _neutralize, redact, scan_injection
from .tshark import PcapError, http_field_rows

HTTP_FIELDS = (
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
)
LOCATORS = ("frame.number", "frame.time_epoch")
MAX_HTTP_ROWS = 25
MAX_FIELD_RECORDS = 200


def capture_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def transform_field(
    value: str,
    field: str,
    *,
    redact_enabled: bool,
) -> dict[str, Any]:
    """Describe actual transformations on one decoded occurrence, before JSON escaping."""
    stripped = value
    if field == "http.request.uri":
        stripped = value.split("?", 1)[0].split("#", 1)[0]
    protected = redact(stripped) if redact_enabled else stripped
    # Scan decoded Unicode, and also scan after control removal to catch split directives.
    hits = scan_injection(protected) + scan_injection(ZERO_WIDTH.sub("", protected))
    display = _neutralize(protected)
    return {
        "display_value": display,
        "injection_kinds": sorted({hit["kind"] for hit in hits}),
        "transformations": {
            "redaction_enabled": redact_enabled,
            "redaction_changed": protected != stripped,
            "uri_suffix_removed": stripped != value,
            "unicode_controls_removed": len(ZERO_WIDTH.findall(protected)),
            "middle_dots_inserted_by_server": display.count("·") - protected.count("·"),
            "middle_dots_in_decoded_source": value.count("·"),
            "neutralization_changed": display != protected,
        },
    }


def build_records(
    rows: list[dict[str, list[str]]],
    *,
    redact_enabled: bool,
) -> tuple[list[dict[str, Any]], bool]:
    records: list[dict[str, Any]] = []
    for row in rows:
        frames = row.get("frame.number", [])
        times = row.get("frame.time_epoch", [])
        if len(frames) != 1 or not frames[0].isdigit() or int(frames[0]) < 1:
            raise PcapError("HTTP evidence requires one valid frame number per row.")
        if len(times) != 1:
            raise PcapError("HTTP evidence requires one timestamp per row.")
        frame = int(frames[0])
        for field in HTTP_FIELDS:
            values = row.get(field, [])
            for occurrence, value in enumerate(values or [""]):
                if len(records) >= MAX_FIELD_RECORDS:
                    return records, True
                records.append(
                    {
                        "record_id": f"F{frame}:{field}/{occurrence}",
                        "frame_number": frame,
                        "frame_time_epoch": times[0],
                        "dissector_creator": row.get("__tshark_creator", ["unknown"])[0],
                        "field": field,
                        "occurrence": occurrence,
                        "present": bool(values),
                        "value_basis": row.get(
                            field + ".__basis",
                            ["tshark_decoded_field_not_wire_bytes"] * len(values or [""]),
                        )[occurrence],
                        "input_decoding": {
                            "tshark_display_replacement_characters": int(
                                row.get(
                                    field + ".__replacement_chars", ["0"] * len(values or [""])
                                )[occurrence]
                            ),
                            "header_envelope_removed": row.get(
                                field + ".__header_envelope", ["false"] * len(values or [""])
                            )[occurrence]
                            == "true",
                            "original_character_encoding_asserted": False,
                        },
                        **transform_field(value, field, redact_enabled=redact_enabled),
                    }
                )
    return records, False


def http_field_evidence(path: Path) -> dict[str, Any]:
    before = capture_digest(path)
    rows, truncated = http_field_rows(
        path, [*LOCATORS, *HTTP_FIELDS], "http.request", MAX_HTTP_ROWS
    )
    records, records_truncated = build_records(rows, redact_enabled=redaction_enabled())
    if capture_digest(path) != before:
        raise PcapError("Capture changed during HTTP extraction; evidence discarded.")
    return {
        "schema": "pcap-mcp.http-fields/v1",
        "capture_sha256": before,
        "capture_modified_by_server": False,
        "extraction": {
            "format": "tshark_pdml_selected_http_fields",
            "display_filter": "http.request",
            "fields": [*LOCATORS, *HTTP_FIELDS],
            "all_occurrences": True,
            "value_basis": "explicit_utf8_if_field_bytes_available_else_tshark_display",
        },
        "observed_requests": len(rows),
        "truncated": truncated or records_truncated,
        "field_records": records,
        "limits": {"http_rows": MAX_HTTP_ROWS, "field_records": MAX_FIELD_RECORDS},
    }


def wrap_field_payload(payload: dict[str, Any]) -> str:
    """Fields were protected once, with their own counters. Do not transform them again."""
    warned = any(record["injection_kinds"] for record in payload["field_records"])
    banner = "SECURITY WARNING: heuristic features in decoded HTTP fields.\n" if warned else ""
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    # Keep peer-controlled closing tags inside JSON, never in the enclosing boundary.
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return (
        banner + "FIELD PROVENANCE: counters apply to each field occurrence; "
        "server-inserted separators come from this pcap-mcp analysis program, "
        "not the captured HTTP server or peer encoding. Zero means no such removal. "
        "PCAP is not written; decoded fields are not raw wire bytes. "
        "Input decoding is recorded per field: strict UTF-8 interpretation of PDML field "
        "bytes is an explicit server choice, not proof of original character encoding. "
        "Tshark display replacement counts describe the upstream tshark display, "
        "not display_value, inserted middle dots, or original control-character counts. "
        "A heuristic match proves neither intent nor attack success.\n"
        f'<untrusted_pcap_data note="{UNTRUSTED_HEADER}">\n{text}\n</untrusted_pcap_data>'
    )

