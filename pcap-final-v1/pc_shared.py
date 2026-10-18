"""Immutable records for the new external Agent batch; no old budgets changed."""
import hashlib
import json
import os
import pc_wire as wire

MODEL = "qwen3:8b"
DIGEST = "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
ANALYSIS_TOOLS = (
    "list_conversations", "inspect_dns_queries", "inspect_http_requests",
    "show_protocol_hierarchy", "find_tcp_anomalies", "analyze_handshake_failures",
    "measure_rtt", "detect_suspicious_patterns", "check_tls_posture",
    "find_cleartext_credentials", "run_display_filter",
)

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)+"\n").encode("utf-8")

def read(path):
    return wire.decode(path.read_bytes())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(value, message):
    if not value:
        raise ValueError(message)

def once(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == data, "Frozen bytes changed: "+path.name)
    else:
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
