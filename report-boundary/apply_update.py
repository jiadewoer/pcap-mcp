"""Add the report boundary without modifying frozen v3 source or existing files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path, *, normalized: bool = False) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data.replace(b"\r\n", b"\n") if normalized else data).hexdigest()


def safe(root: Path, relative: str, *, base: bool = False) -> Path:
    path = Path(relative)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or "\\" in relative
        or ":" in relative
        or path.parts[0]
        not in (
            {"src", "pyproject.toml", "uv.lock"} if base else {"report-boundary", "tests", "docs"}
        )
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


def apply(project: Path, package: Path, *, check: bool = False) -> None:
    project, package = project.resolve(), package.resolve()
    manifest = json.loads((package / "update-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "report-boundary-v1":
        raise ValueError("Unknown update version.")
    bases = manifest["base_sha256"]
    expected_modules = {name for name in bases if name.startswith("src/pcap_mcp/")}
    actual_modules = {
        p.relative_to(project).as_posix() for p in (project / "src/pcap_mcp").glob("*.py")
    }
    if not expected_modules or actual_modules != expected_modules:
        raise ValueError("Frozen v3 module inventory differs. Nothing written.")
    for relative, expected in bases.items():
        target = safe(project, relative, base=True)
        if not target.is_file() or digest(target) != expected:
            raise ValueError("Frozen base differs: " + relative + ". Nothing written.")
    pending, seen = [], set()
    for row in manifest["files"]:
        relative = row["path"]
        if relative in seen:
            raise ValueError("Duplicate update path.")
        seen.add(relative)
        source, target = safe(package / "payload", relative), safe(project, relative)
        expected = row["sha256_normalized"]
        if not source.is_file() or digest(source, normalized=True) != expected:
            raise ValueError("Corrupt payload: " + relative)
        if target.exists():
            if not target.is_file() or digest(target, normalized=True) != expected:
                raise ValueError("Existing addition differs: " + relative + ". Nothing written.")
        else:
            pending.append((source, target))
    print(f"Validated {len(pending)} additions; byte-frozen v3 and dependency files matched.")
    if check:
        return
    written = []
    try:
        for source, target in pending:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                written.append(target)
                handle.write(source.read_bytes())
    except OSError:
        for target in reversed(written):
            target.unlink(missing_ok=True)
        raise
    print(
        "Ready: powershell -NoProfile -ExecutionPolicy Bypass "
        "-File .\\report-boundary\\Run-ReportBoundary.ps1"
    )


def main() -> None:
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
