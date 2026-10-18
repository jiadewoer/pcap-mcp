"""Hardened tshark subprocess boundary: paths, arguments, limits and decoding."""

from __future__ import annotations

import re
import subprocess
import threading
from pathlib import Path
from typing import BinaryIO

from .config import get_settings

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap", ".ntar"}
_FILTER_OK = re.compile(r"^[A-Za-z0-9_.:\[\]\"'/\\ ()<>=!&|+*^~,%$-]{0,512}$")
_FIELD_OK = re.compile(r"^[A-Za-z0-9_.]{1,96}$")
_STAT_OK = re.compile(r"^(io,phs|conv,(tcp|udp|ip)|endpoints,(tcp|udp|ip))$")


class PcapError(RuntimeError):
    """A safe, user-presentable capture-analysis error."""


def resolve_capture(path_str: str) -> Path:
    settings = get_settings()
    if not settings.allowed_dirs:
        raise PcapError(
            "PCAP_MCP_ALLOWED_DIRS is not configured; file access is denied by default."
        )
    path = Path(path_str).expanduser()
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise PcapError("Capture does not exist or is inaccessible.") from exc
    if not path.is_file():
        raise PcapError("The capture path must be a regular file.")
    if path.suffix.lower() not in _ALLOWED_SUFFIXES:
        raise PcapError("Unsupported capture type; use .pcap, .pcapng, .cap, or .ntar.")
    if not any(_under(path, directory) for directory in settings.allowed_dirs):
        raise PcapError("The capture is outside the configured allowed directories.")
    size_mb = path.stat().st_size / 1024**2
    if size_mb > settings.max_file_mb:
        raise PcapError(f"Capture is {size_mb:.1f} MB, above the {settings.max_file_mb} MB limit.")
    return path


def _under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def validate_filter(expression: str) -> str:
    if not _FILTER_OK.fullmatch(expression):
        raise PcapError("Display filter contains forbidden characters or is too long.")
    if expression.lstrip().startswith("-"):
        raise PcapError("Display filter cannot start with '-'.")
    return expression


def validate_fields(names: list[str]) -> list[str]:
    if not names or len(names) > 32:
        raise PcapError("Choose between 1 and 32 output fields.")
    if any(not _FIELD_OK.fullmatch(name) for name in names):
        raise PcapError("A field name contains unsupported characters.")
    return names


def _run(args: list[str]) -> str:
    """Collect bounded command output, including on Windows where select() cannot read pipes."""
    settings = get_settings()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    reader_error = threading.Event()
    timed_out = False

    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_NO_WINDOW,
            shell=False,
        )
    except OSError as exc:
        raise PcapError("Could not start the Wireshark command.") from exc

    def collect(stream: BinaryIO, chunks: list[bytes], limit: int) -> None:
        size = 0
        # A separate reader for each pipe prevents stderr from blocking stdout.
        try:
            while data := stream.read(64 * 1024):
                size += len(data)
                if size > limit:
                    overflow.set()
                    process.kill()
                    return
                chunks.append(data)
        except OSError:
            reader_error.set()
            if process.poll() is None:
                process.kill()

    assert process.stdout is not None and process.stderr is not None
    out_reader = threading.Thread(
        target=collect,
        args=(process.stdout, stdout_chunks, settings.max_output_mb * 1024**2),
        daemon=True,
    )
    err_reader = threading.Thread(
        target=collect, args=(process.stderr, stderr_chunks, 64 * 1024), daemon=True
    )
    out_reader.start()
    err_reader.start()
    try:
        process.wait(timeout=settings.timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    finally:
        out_reader.join()
        err_reader.join()
        process.stdout.close()
        process.stderr.close()

    if timed_out:
        raise PcapError(f"Analysis exceeded the {settings.timeout_s}s timeout.")
    if overflow.is_set():
        raise PcapError("Wireshark output exceeded the configured size limit.")
    if reader_error.is_set():
        raise PcapError("Could not read the Wireshark command output.")
    if process.returncode != 0:
        # The diagnostic may contain a path or attacker-controlled packet content.
        raise PcapError("Wireshark could not analyze this capture or display filter.")
    return b"".join(stdout_chunks).decode("utf-8", errors="replace")


def capinfos(path: Path) -> dict[str, str]:
    output = _run([get_settings().capinfos, "-M", str(path)])
    info: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def stat(path: Path, spec: str) -> str:
    if not _STAT_OK.fullmatch(spec):
        raise PcapError("Unsupported tshark statistics module.")
    return _run([get_settings().tshark, "-r", str(path), "-q", "-z", spec])


def fields(
    path: Path,
    field_names: list[str],
    display_filter: str = "",
    limit: int | None = None,
) -> tuple[list[dict[str, str]], bool]:
    settings = get_settings()
    names = validate_fields(field_names)
    cap = settings.max_rows if limit is None else min(max(1, limit), 20_000)
    args = [
        settings.tshark,
        "-r",
        str(path),
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    if display_filter:
        args += ["-Y", validate_filter(display_filter)]
    for name in names:
        args += ["-e", name]
    rows: list[dict[str, str]] = []
    truncated = False
    for line in _run(args).splitlines():
        if not line.strip():
            continue
        if len(rows) >= cap:
            truncated = True
            break
        parts = line.split("\t")
        parts += [""] * (len(names) - len(parts))
        rows.append(dict(zip(names, parts[: len(names)], strict=False)))
    return rows, truncated


def http_field_rows(
    path: Path,
    field_names: list[str],
    display_filter: str,
    limit: int,
) -> tuple[list[dict[str, list[str]]], bool]:
    """Select HTTP PDML fields; explicitly decode available field bytes as strict UTF-8.

    Wireshark's HTTP string display can replace every high-bit byte with U+FFFD.
    PDML gives both the display and field bytes. Header field byte ranges include
    their header name and CRLF; remove that envelope before decoding. These are
    dissector field bytes, potentially from a reassembled data source.
    """
    import xml.etree.ElementTree as ET

    names = validate_fields(field_names)
    allowed = {
        "frame.number",
        "frame.time_epoch",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.user_agent",
    }
    if not set(names) <= allowed:
        raise PcapError("HTTP evidence uses only its fixed metadata fields.")
    cap = min(max(1, limit), get_settings().max_rows)
    text = _run(
        [
            get_settings().tshark,
            "-n",
            "-r",
            str(path),
            "-T",
            "pdml",
            "-J",
            "frame http",
            "-Y",
            validate_filter(display_filter),
        ]
    )
    try:
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise ValueError("DTD is not accepted")
        root = ET.fromstring(text)
        if root.tag != "pdml":
            raise ValueError("Wrong document type")
        packets = root.findall("packet")
        rows = []
        for packet in packets[:cap]:
            row: dict[str, list[str]] = {name: [] for name in names}
            row["__tshark_creator"] = [root.get("creator", "unknown")]
            for node in packet.iter("field"):
                name = node.get("name", "")
                if name not in row:
                    continue
                display = node.get("show", "")
                value = display
                basis = "tshark_display_only"
                envelope = False
                if name.startswith("http.") and node.get("value") is not None:
                    try:
                        raw = bytes.fromhex(node.get("value", ""))
                        if name in {"http.host", "http.user_agent"}:
                            header = b"host" if name == "http.host" else b"user-agent"
                            label, sep, contents = raw.partition(b":")
                            if not sep or label.lower() != header:
                                raise ValueError("Unexpected header byte range")
                            raw = contents.removesuffix(b"\r\n").strip(b" \t")
                            envelope = True
                        value = raw.decode("utf-8", errors="strict")
                        basis = "strict_utf8_interpretation_of_pdml_field_bytes"
                    except (ValueError, UnicodeDecodeError):
                        # Never guess back from U+FFFD or decode malformed hex permissively.
                        basis = "tshark_display_only_utf8_unavailable"
                        value = display
                        envelope = False
                row[name].append(value)
                row.setdefault(name + ".__basis", []).append(basis)
                row.setdefault(name + ".__replacement_chars", []).append(
                    str(display.count("\ufffd"))
                )
                row.setdefault(name + ".__header_envelope", []).append(str(envelope).lower())
            rows.append(row)
    except (ET.ParseError, ValueError, TypeError) as exc:
        raise PcapError("Wireshark returned unsupported HTTP PDML field output.") from exc
    return rows, len(packets) > cap
