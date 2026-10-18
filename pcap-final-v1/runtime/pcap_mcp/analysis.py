"""Packet-analysis functions. Every function returns structured, bounded data."""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from math import ceil, isfinite
from pathlib import Path
from typing import Any

from .tshark import PcapError, capinfos, fields, stat

_PHS_LINE = re.compile(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)")


def _src(row: dict[str, str]) -> str:
    """Return the source address for either IPv4 or IPv6 traffic."""
    return row.get("ip.src") or row.get("ipv6.src") or ""


def _dst(row: dict[str, str]) -> str:
    """Return the destination address for either IPv4 or IPv6 traffic."""
    return row.get("ip.dst") or row.get("ipv6.dst") or ""


def _parse_phs(text: str) -> list[dict[str, Any]]:
    protocols: list[dict[str, Any]] = []
    parents: list[str] = []
    for line in text.splitlines():
        match = _PHS_LINE.match(line)
        if match:
            depth = len(match.group(1)) // 2
            protocol = match.group(2)
            parents[depth:] = [protocol]
            protocols.append(
                {
                    "depth": depth,
                    "protocol": protocol,
                    "path": ":".join(parents),
                    "frames": int(match.group(3)),
                    "bytes": int(match.group(4)),
                }
            )
    return protocols


def _aggregate_protocols(protocols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    totals: defaultdict[str, dict[str, int]] = defaultdict(lambda: {"frames": 0, "bytes": 0})
    for item in protocols:
        protocol = str(item["protocol"])
        totals[protocol]["frames"] += int(item["frames"])
        totals[protocol]["bytes"] += int(item["bytes"])
    return sorted(
        (
            {"protocol": protocol, "frames": values["frames"], "bytes": values["bytes"]}
            for protocol, values in totals.items()
        ),
        key=lambda item: -int(item["frames"]),
    )


def summarize(path: Path) -> dict[str, Any]:
    info = capinfos(path)
    protocols = _parse_phs(stat(path, "io,phs"))
    endpoints, truncated = fields(path, ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"], limit=20_000)
    counts: Counter[str] = Counter()
    for row in endpoints:
        counts.update(value for value in (_src(row), _dst(row)) if value)
    return {
        "file": path.name,
        "packets": info.get("Number of packets", "?"),
        "duration": info.get("Capture duration", "?"),
        "first_packet": info.get("First packet time", "?"),
        "bytes": info.get("File size", "?"),
        "top_protocols": _aggregate_protocols(protocols)[:12],
        "top_talkers": [{"ip": ip, "packets": count} for ip, count in counts.most_common(10)],
        "endpoint_scan_truncated": truncated,
    }


def conversations(path: Path, proto: str = "tcp", top_n: int = 20) -> dict[str, Any]:
    protocol = proto.lower()
    if protocol not in {"tcp", "udp", "ip"}:
        raise PcapError("Protocol must be tcp, udp, or ip.")
    top_n = min(max(int(top_n), 1), 100)
    transport_fields = [] if protocol == "ip" else [f"{protocol}.srcport", f"{protocol}.dstport"]
    packet_rows, truncated = fields(
        path,
        ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst", *transport_fields, "frame.len"],
        display_filter="ip || ipv6" if protocol == "ip" else protocol,
        limit=20_000,
    )
    totals: defaultdict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"frames": 0, "bytes": 0}
    )
    for packet in packet_rows:
        src_address, dst_address = _src(packet), _dst(packet)
        if not src_address or not dst_address:
            continue
        if protocol == "ip":
            src, dst = src_address, dst_address
        else:
            src = _format_endpoint(src_address, packet.get(f"{protocol}.srcport", ""))
            dst = _format_endpoint(dst_address, packet.get(f"{protocol}.dstport", ""))
        endpoint_a, endpoint_b = sorted((src, dst))
        try:
            length = int(packet.get("frame.len", "0"))
        except ValueError:
            length = 0
        totals[(endpoint_a, endpoint_b)]["frames"] += 1
        totals[(endpoint_a, endpoint_b)]["bytes"] += length
    rows: list[dict[str, Any]] = [
        {
            "endpoint_a": endpoints[0],
            "endpoint_b": endpoints[1],
            "frames": values["frames"],
            "bytes": values["bytes"],
        }
        for endpoints, values in totals.items()
    ]
    rows.sort(key=lambda item: -int(item["bytes"]))
    return {
        "protocol": protocol,
        "total": len(rows),
        "truncated": truncated,
        "conversations": rows[:top_n],
    }


def _format_endpoint(address: str, port: str) -> str:
    if not port:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def dns_queries(path: Path) -> dict[str, Any]:
    rows, truncated = fields(
        path,
        [
            "frame.number",
            "ip.src",
            "ipv6.src",
            "dns.qry.name",
            "dns.qry.type",
            "dns.a",
            "dns.aaaa",
            "dns.flags.rcode",
            "dns.flags.response",
        ],
        display_filter="dns",
    )
    names = Counter(
        row["dns.qry.name"]
        for row in rows
        if row.get("dns.qry.name") and str(row.get("dns.flags.response", "")).casefold() in {"0", "false"}
    )
    return {
        "observed_dns_packets": len(rows),
        "truncated": truncated,
        "unique_names_in_sample": len(names),
        "top_names": names.most_common(20),
        "nxdomain_count_in_sample": sum(
            str(row.get("dns.flags.response", "")).casefold() in {"1", "true"}
            and row.get("dns.flags.rcode") == "3"
            for row in rows
        ),
        "queries": rows[:50],
    }


def http_requests(path: Path) -> dict[str, Any]:
    rows, truncated = fields(
        path,
        [
            "frame.number",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.user_agent",
        ],
        display_filter="http.request",
    )
    # Query strings commonly contain session tokens, including names unknown to the redactor.
    for row in rows:
        if uri := row.get("http.request.uri"):
            row["http.request.uri"] = uri.split("?", 1)[0].split("#", 1)[0]
    return {
        "observed_requests": len(rows),
        "truncated": truncated,
        "distinct_hosts_in_sample": len({row["http.host"] for row in rows if row.get("http.host")}),
        "top_user_agents": Counter(
            row["http.user_agent"] for row in rows if row.get("http.user_agent")
        ).most_common(5),
        "requests": rows,
    }


def protocol_hierarchy(path: Path) -> dict[str, Any]:
    hierarchy = _parse_phs(stat(path, "io,phs"))
    return {"hierarchy": hierarchy, "protocol_totals": _aggregate_protocols(hierarchy)}


def tcp_anomalies(path: Path) -> dict[str, Any]:
    rows, truncated = fields(
        path,
        [
            "frame.number",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.stream",
            "_ws.expert.message",
        ],
        display_filter="tcp.analysis.flags && !tcp.analysis.window_update",
        limit=1000,
    )
    kinds = Counter(row["_ws.expert.message"] for row in rows if row.get("_ws.expert.message"))
    streams = Counter(row["tcp.stream"] for row in rows if row.get("tcp.stream"))
    joined = " ".join(kinds).lower()
    hints: list[str] = []
    if "retransmission" in joined:
        hints.append("Retransmissions suggest packet loss, congestion, or a slow peer.")
    if "zero window" in joined:
        hints.append("Zero-window events suggest the receiver application is not draining buffers.")
    if "out-of-order" in joined:
        hints.append(
            "Out-of-order delivery may indicate multipath routing or reordering on the path."
        )
    if "duplicate ack" in joined:
        hints.append(
            "Duplicate ACKs commonly accompany loss or reordering; inspect the affected streams."
        )
    if not rows:
        hints.append(
            "No tshark TCP analysis flags were found; the issue may be outside the transport layer."
        )
    return {
        "observed_anomaly_packets": len(rows),
        "truncated": truncated,
        "by_type": kinds.most_common(),
        "worst_streams": [
            {"tcp_stream": stream, "anomalies": count} for stream, count in streams.most_common(5)
        ],
        "hints": hints,
    }


def handshake_failures(path: Path) -> dict[str, Any]:
    events, truncated = fields(
        path,
        [
            "frame.number",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "tcp.flags.syn",
            "tcp.flags.ack",
            "tcp.flags.reset",
        ],
        display_filter="tcp.flags.syn==1 || tcp.flags.reset==1",
        limit=6000,
    )
    attempts: dict[str, dict[str, Any]] = {}
    for row in events:
        stream = row.get("tcp.stream", "")
        src, dst = _src(row), _dst(row)
        if not stream or not src or not dst:
            continue
        if row.get("tcp.flags.syn") == "1" and row.get("tcp.flags.ack") == "0":
            if stream not in attempts:
                attempts[stream] = {
                    "src": src,
                    "dst": dst,
                    "sport": row.get("tcp.srcport", ""),
                    "dport": row.get("tcp.dstport", ""),
                    "syn_count": 1,
                    "state": "pending",
                }
            elif src == attempts[stream]["src"] and dst == attempts[stream]["dst"]:
                attempts[stream]["syn_count"] += 1
            continue
        attempt = attempts.get(stream)
        if not attempt or src != attempt["dst"] or dst != attempt["src"]:
            continue
        if row.get("tcp.srcport") != attempt["dport"] or row.get("tcp.dstport") != attempt["sport"]:
            continue
        if row.get("tcp.flags.syn") == "1" and row.get("tcp.flags.ack") == "1":
            attempt["state"] = "synack"
        elif row.get("tcp.flags.reset") == "1" and attempt["state"] == "pending":
            attempt["state"] = "reset"
    refused: list[dict[str, Any]] = []
    unanswered: list[dict[str, Any]] = []
    succeeded = 0
    for stream, attempt in attempts.items():
        item = {
            "tcp_stream": stream,
            "dst": attempt["dst"],
            "dport": attempt["dport"],
            "syn_count": attempt["syn_count"],
        }
        if attempt["state"] == "synack":
            succeeded += 1
        elif attempt["state"] == "reset":
            refused.append(item)
        else:
            unanswered.append(item)
    verdict: list[str] = []
    if refused:
        verdict.append(
            f"{len(refused)} stream(s) received a server RST before any observed SYN-ACK."
        )
    if unanswered:
        verdict.append(
            f"{len(unanswered)} stream(s) had no observed reply; the capture may be incomplete."
        )
    if not refused and not unanswered:
        verdict.append("Every observed initial SYN was followed by a server SYN-ACK.")
    return {
        "attempts": len(attempts),
        "succeeded": succeeded,
        "refused_by_rst": refused[:20],
        "no_response": unanswered[:20],
        "truncated": truncated,
        "verdict": verdict,
    }


def _percentile(sorted_values: list[float], percentile: float) -> float:
    """Nearest-rank percentile for an already sorted, nonempty sample."""
    index = max(0, min(len(sorted_values) - 1, ceil(len(sorted_values) * percentile) - 1))
    return sorted_values[index]


def rtt_stats(path: Path, tcp_stream: int | None = None) -> dict[str, Any]:
    display_filter = "tcp.analysis.ack_rtt"
    if tcp_stream is not None:
        display_filter += f" && tcp.stream=={int(tcp_stream)}"
    rows, truncated = fields(
        path, ["tcp.stream", "tcp.analysis.ack_rtt"], display_filter=display_filter, limit=5000
    )
    values: list[float] = []
    for row in rows:
        try:
            value = float(row["tcp.analysis.ack_rtt"]) * 1000
            if isfinite(value) and value >= 0:
                values.append(value)
        except (ValueError, KeyError):
            continue
    if not values:
        return {"samples": 0, "truncated": truncated, "note": "No usable ACK RTT samples."}
    values.sort()
    return {
        "samples": len(values),
        "truncated": truncated,
        "min_ms": round(values[0], 2),
        "p50_ms": round(statistics.median(values), 2),
        "p95_ms": round(_percentile(values, 0.95), 2),
        "max_ms": round(values[-1], 2),
        "mean_ms": round(statistics.mean(values), 2),
        "jitter_ms": round(statistics.pstdev(values), 2),
    }


def suspicious_patterns(path: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    syn, syn_truncated = fields(
        path,
        [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.dstport",
        ],
        display_filter="tcp.flags.syn==1 && tcp.flags.ack==0",
        limit=20_000,
    )
    scan: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    groups: defaultdict[tuple[str, str, str], list[float]] = defaultdict(list)
    for row in syn:
        src, dst, port = _src(row), _dst(row), row.get("tcp.dstport", "")
        if src and port:
            scan[(src, dst)].add(port)
        try:
            groups[(src, dst, port)].append(float(row["frame.time_epoch"]))
        except (ValueError, KeyError):
            pass
    for (src, dst), ports in scan.items():
        if len(ports) >= 20:
            findings.append(
                {
                    "type": "port_scan",
                    "severity": "medium",
                    "detail": f"{src} contacted {len(ports)} ports on {dst}.",
                }
            )
    for (src, dst, port), times in groups.items():
        if len(times) < 6:
            continue
        times.sort()
        gaps = [later - earlier for earlier, later in zip(times, times[1:], strict=False)]
        mean = statistics.mean(gaps)
        if mean > 5 and statistics.pstdev(gaps) / mean < 0.15:
            findings.append(
                {
                    "type": "beacon",
                    "severity": "high",
                    "detail": (
                        f"{src} -> {dst}:{port} repeated about every {mean:.0f}s "
                        f"({len(times)} attempts)."
                    ),
                }
            )
    dns, dns_truncated = fields(
        path, ["dns.qry.name", "dns.qry.type"], display_filter="dns.flags.response==0", limit=20_000
    )
    long_labels = sum(
        bool(name) and max((len(label) for label in name.split(".")), default=0) > 40
        for name in (row.get("dns.qry.name", "") for row in dns)
    )
    txt_like = sum(row.get("dns.qry.type") in {"10", "16"} for row in dns)
    if long_labels >= 10:
        findings.append(
            {
                "type": "dns_tunnel",
                "severity": "high",
                "detail": f"Found {long_labels} unusually long DNS labels.",
            }
        )
    if dns and txt_like / len(dns) > 0.3:
        findings.append(
            {
                "type": "dns_tunnel",
                "severity": "medium",
                "detail": f"TXT/NULL queries were {txt_like / len(dns):.0%} of DNS traffic.",
            }
        )
    return {
        "findings": findings
        or [{"type": "none", "severity": "info", "detail": "No implemented heuristic matched."}],
        "truncated": syn_truncated or dns_truncated,
        "disclaimer": (
            "Heuristic leads only, not a detection verdict; review matching traffic manually."
        ),
    }


def tls_posture(path: Path) -> dict[str, Any]:
    rows, truncated = fields(
        path,
        [
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tls.handshake.version",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.type",
            "tls.handshake.extensions_server_name",
        ],
        display_filter="tls.handshake.type==2 || tls.handshake.type==1",
        limit=2000,
    )
    # ClientHello advertises capabilities; only ServerHello selects a version.
    server_hellos = [row for row in rows if row.get("tls.handshake.type") == "2"]
    versions = Counter(
        row.get("tls.handshake.extensions.supported_version") or row["tls.handshake.version"]
        for row in server_hellos
        if row.get("tls.handshake.extensions.supported_version") or row.get("tls.handshake.version")
    )
    legacy = {"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1"}
    sni = Counter(
        row["tls.handshake.extensions_server_name"]
        for row in rows
        if row.get("tls.handshake.extensions_server_name")
    )
    return {
        "handshakes": len(server_hellos),
        "observed_hello_packets": len(rows),
        "truncated": truncated,
        "version_distribution": versions.most_common(),
        "outdated_versions": [
            {"version": legacy[version], "count": count}
            for version, count in versions.items()
            if version in legacy
        ],
        "top_sni": sni.most_common(15),
    }


def cleartext_credentials(path: Path) -> dict[str, Any]:
    rows, truncated = fields(
        path,
        ["frame.number", "frame.protocols"],
        display_filter=(
            'http.authorization || ftp.request.command == "PASS" || telnet '
            '|| pop.request.command == "PASS" || imap.request contains "LOGIN" '
            '|| (http.request.method == "POST" && http.content_type contains "urlencoded")'
        ),
        limit=500,
    )
    return {
        "count": len(rows),
        "truncated": truncated,
        "locations": [
            {"frame": row.get("frame.number"), "protocols": row.get("frame.protocols")}
            for row in rows[:50]
        ],
        "note": (
            "Credential values are never returned. Inspect listed frames only in a controlled "
            "environment."
        ),
    }


_SAFE_DISPLAY_FIELDS = {
    "frame.number",
    "frame.time_relative",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.type",
    "dns.flags.rcode",
    "http.request.method",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
}
_SAFE_FILTER_FIELDS = _SAFE_DISPLAY_FIELDS | {
    "ip",
    "ipv6",
    "tcp",
    "udp",
    "dns",
    "http.request",
    "tls",
    "vlan",
    "ip.addr",
    "ipv6.addr",
    "tcp.port",
    "udp.port",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tls.handshake.type",
    "dns.qry.name",
    "http.host",
}
_FILTER_WORDS = {"and", "or", "not", "contains", "in", "true", "false"}
_PROTOCOL_FILTER_FIELDS = {"ip", "ipv6", "tcp", "udp", "dns", "http.request", "tls", "vlan"}
_QUOTED_FILTER_TEXT = re.compile(r'"(?:\\.|[^"\\])*"')
_FILTER_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")


def _validate_custom_filter(expression: str) -> None:
    """Deny raw-byte predicates, which otherwise act as a payload guessing oracle."""
    if "[" in expression or "]" in expression or "'" in expression:
        raise PcapError("Use metadata fields and double-quoted values in display filters.")
    without_strings = _QUOTED_FILTER_TEXT.sub(" ", expression)
    without_strings = re.sub(r"\b0x[0-9a-fA-F]+\b", "0", without_strings)
    if '"' in without_strings:
        raise PcapError("Display filter contains an unterminated quoted value.")
    for match in _FILTER_IDENTIFIER.finditer(without_strings):
        word = match.group(0).lower()
        if word not in _SAFE_FILTER_FIELDS and word not in _FILTER_WORDS:
            raise PcapError("Display filter refers to a field outside approved metadata.")
        if word in _PROTOCOL_FILTER_FIELDS:
            suffix = without_strings[match.end() :].lstrip().lower()
            if suffix.startswith(("contains", "matches", "==", "!=", "<", ">")):
                raise PcapError("Raw protocol content tests are not allowed.")


def display_filter(path: Path, expression: str, names: list[str]) -> dict[str, Any]:
    if not set(names) <= _SAFE_DISPLAY_FIELDS:
        raise PcapError("Only approved packet metadata fields may be extracted.")
    _validate_custom_filter(expression)
    rows, truncated = fields(path, names, expression)
    return {"filter": expression, "rows": rows, "truncated": truncated}
