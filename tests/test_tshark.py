import sys
from pathlib import Path

import pytest

from pcap_mcp import config, tshark
from pcap_mcp.config import Settings
from pcap_mcp.tshark import PcapError, _run, resolve_capture, validate_fields, validate_filter


def settings_for(directory: Path, **overrides) -> Settings:
    values = {
        "tshark": "tshark",
        "capinfos": "capinfos",
        "allowed_dirs": (directory.resolve(),),
        "max_file_mb": 1,
        "max_rows": 200,
        "timeout_s": 5,
        "max_output_mb": 16,
        "max_result_chars": 50_000,
        "redact": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize("bad", ["tcp; whoami", "tcp && `whoami`", "tcp\nip", "-r secret.pcap"])
def test_filter_rejects_injection(bad):
    with pytest.raises(PcapError):
        validate_filter(bad)


@pytest.mark.parametrize(
    "valid", ["http.request", "tcp.port == 443", 'dns.qry.name contains "evil"']
)
def test_filter_accepts_normal_wireshark_syntax(valid):
    assert validate_filter(valid) == valid


def test_fields_are_validated():
    assert validate_fields(["frame.number", "_ws.col.Info"]) == ["frame.number", "_ws.col.Info"]
    with pytest.raises(PcapError):
        validate_fields(["frame.number", "-r"])


def test_capture_outside_allowlist_is_rejected(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"pcap")
    monkeypatch.setattr(config, "_SETTINGS", settings_for(allowed))
    with pytest.raises(PcapError, match="outside"):
        resolve_capture(str(outside))


def test_capture_inside_allowlist_is_resolved(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    capture = allowed / "sample.pcapng"
    capture.write_bytes(b"pcap")
    monkeypatch.setattr(config, "_SETTINGS", settings_for(allowed))
    assert resolve_capture(str(capture)) == capture.resolve()


def test_capture_size_and_suffix_are_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path, max_file_mb=1))
    wrong = tmp_path / "notes.txt"
    wrong.write_text("x")
    with pytest.raises(PcapError, match="Unsupported"):
        resolve_capture(str(wrong))
    large = tmp_path / "large.pcap"
    large.write_bytes(b"0" * (1024**2 + 1))
    with pytest.raises(PcapError, match="above"):
        resolve_capture(str(large))


def test_empty_allowlist_denies_everything(tmp_path, monkeypatch):
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"pcap")
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path, allowed_dirs=()))
    with pytest.raises(PcapError, match="denied by default"):
        resolve_capture(str(capture))


def test_nonzero_exit_with_partial_stdout_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path))
    with pytest.raises(PcapError, match="could not analyze"):
        _run([sys.executable, "-c", "import sys; print('partial'); sys.exit(2)"])


def test_subprocess_stdout_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path, max_output_mb=1))
    with pytest.raises(PcapError, match="output exceeded"):
        _run([sys.executable, "-c", "import sys; sys.stdout.write('x' * 1100000)"])


def test_subprocess_timeout_terminates_child(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path, timeout_s=1))
    with pytest.raises(PcapError, match="exceeded the 1s timeout"):
        _run([sys.executable, "-c", "import time; time.sleep(10)"])


def test_fields_keep_column_alignment_and_report_sampling(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_SETTINGS", settings_for(tmp_path, max_rows=2))
    commands = []

    def fake_run(args):
        commands.append(args)
        return "1\t10.0.0.1\n2\t\n3\t10.0.0.3\n"

    monkeypatch.setattr(tshark, "_run", fake_run)
    rows, truncated = tshark.fields(
        tmp_path / "sample.pcap", ["frame.number", "ip.src"], display_filter="ip"
    )
    assert rows == [
        {"frame.number": "1", "ip.src": "10.0.0.1"},
        {"frame.number": "2", "ip.src": ""},
    ]
    assert truncated is True
    assert commands[0][-6:] == ["-Y", "ip", "-e", "frame.number", "-e", "ip.src"]
