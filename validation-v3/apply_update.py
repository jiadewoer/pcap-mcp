"""Add this extension to the original project; never overwrite existing code."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def safe(root: Path, relative: str) -> Path:
    path = Path(relative)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or "\\" in relative
        or path.parts[0] not in {"src", "tests", "docs", "validation-v3"}
    ):
        raise ValueError("Unsafe update path.")
    target = root / path
    for item in (target, *target.parents):
        if item == root.parent:
            break
        if item.is_symlink():
            raise ValueError("Symlink in update path.")
    if not target.resolve().is_relative_to(root):
        raise ValueError("Update escapes project.")
    return target


def apply(project: Path, package: Path, *, check: bool = False):
    project, package = project.resolve(), package.resolve()
    if not (project / "pyproject.toml").is_file():
        raise ValueError("Original project must contain pyproject.toml.")
    manifest = json.loads((package / "update-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "agent-v3-validation-v1":
        raise ValueError("Unknown update version.")
    for relative, expected in manifest["base_sha256_normalized"].items():
        target = safe(project, relative)
        if not target.is_file() or digest(target) != expected:
            raise ValueError("Current source differs: " + relative + ". Nothing written.")
    pending, seen = [], set()
    for row in manifest["files"]:
        relative = row["path"]
        if relative in seen:
            raise ValueError("Duplicate update path.")
        seen.add(relative)
        source, target = safe(package / "payload", relative), safe(project, relative)
        if not source.is_file() or digest(source) != row["sha256_normalized"]:
            raise ValueError("Corrupt payload: " + relative)
        if target.exists():
            if not target.is_file() or digest(target) != row["sha256_normalized"]:
                raise ValueError("Existing file differs: " + relative + ". Nothing written.")
        else:
            pending.append((source, target))
    print(f"Validated {len(pending)} additions; original code and existing environment retained.")
    if check:
        return
    written = []
    try:
        for source, target in pending:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation avoids overwriting a file added after preflight.
            with target.open("xb") as handle:
                written.append(target)
                handle.write(source.read_bytes())
    except OSError:
        for target in reversed(written):
            target.unlink(missing_ok=True)
        raise
    print(
        "Ready: powershell -NoProfile -ExecutionPolicy Bypass "
        "-File .\\validation-v3\\Run-Validation.ps1"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        apply(args.project, Path(__file__).resolve().parent, check=args.check)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"Update stopped: {exc}\n")


if __name__ == "__main__":
    main()
