"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

_TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def _find(name: str, candidates: list[str]) -> str:
    if executable := shutil.which(name):
        return executable
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError(
        f"Cannot find {name}. Install Wireshark and add its installation directory to PATH."
    )


def _dirs(name: str) -> tuple[Path, ...]:
    raw = os.getenv(name, "")
    return tuple(
        Path(item.strip()).expanduser().resolve() for item in raw.split(os.pathsep) if item.strip()
    )


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value


@dataclass(frozen=True)
class Settings:
    """Server limits. Empty ``allowed_dirs`` intentionally denies all file access."""

    tshark: str = field(default_factory=lambda: _find("tshark", _TSHARK_CANDIDATES))
    capinfos: str = field(
        default_factory=lambda: _find(
            "capinfos",
            [candidate.replace("tshark", "capinfos") for candidate in _TSHARK_CANDIDATES],
        )
    )
    allowed_dirs: tuple[Path, ...] = field(default_factory=lambda: _dirs("PCAP_MCP_ALLOWED_DIRS"))
    max_file_mb: int = field(default_factory=lambda: _positive_int("PCAP_MCP_MAX_FILE_MB", 200))
    max_rows: int = field(default_factory=lambda: _positive_int("PCAP_MCP_MAX_ROWS", 200))
    timeout_s: int = field(default_factory=lambda: _positive_int("PCAP_MCP_TIMEOUT_S", 60))
    redact: bool = field(
        default_factory=lambda: os.getenv("PCAP_MCP_REDACT", "on").lower() != "off"
    )


_SETTINGS: Settings | None = None


def get_settings() -> Settings:
    """Lazily load settings so importing pure security helpers does not require Wireshark."""
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings()
    return _SETTINGS


def redaction_enabled() -> bool:
    """Read the output policy without requiring tshark discovery."""
    if _SETTINGS is not None:
        return _SETTINGS.redact
    return os.getenv("PCAP_MCP_REDACT", "on").lower() != "off"


def reset_settings() -> None:
    """Clear the settings cache. Intended for tests and controlled reconfiguration."""
    global _SETTINGS
    _SETTINGS = None
