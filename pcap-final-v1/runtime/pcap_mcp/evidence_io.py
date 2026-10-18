"""Decode complete protected tool envelopes without importing a capture backend."""

from __future__ import annotations

import json
from typing import Any


def parse_tool_payload(text: str) -> dict[str, Any] | None:
    if "client-side output limit reached" in text:
        return None
    marker = '<untrusted_pcap_data note="'
    if marker in text:
        _, _, body = text.partition(marker)
        _, sep, body = body.partition('\">\n')
        if not sep or not body.endswith("\n</untrusted_pcap_data>"):
            return None
        text = body[: -len("\n</untrusted_pcap_data>")]
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None
