"""Hardened tshark subprocess boundary: paths, arguments, limits and decoding."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

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
        raise PcapError(f"Capture does not exist or is inaccessible: {path_str}") from exc
    if not path.is_file():
        raise PcapError("The capture path must be a regular file.")
    if path.suffix.lower() not in _ALLOWED_SUFFIXES:
        raise PcapError(f"Unsupported capture type: {path.suffix}")
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
    settings = get_settings()
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=settings.timeout_s,
            creationflags=_NO_WINDOW,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PcapError(f"Analysis exceeded the {settings.timeout_s}s timeout.") from exc
    except OSError as exc:
        raise PcapError(f"Could not start Wireshark command: {exc}") from exc
    if result.returncode != 0 and not result.stdout:
        detail = (result.stderr or "unknown tshark error").strip()[:300]
        raise PcapError(f"tshark failed: {detail}")
    return result.stdout


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
