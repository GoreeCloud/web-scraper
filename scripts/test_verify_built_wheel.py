"""Negative tests for the wheel integrity verifier (stdlib only).

Run after building the deterministic wheel. Creates tampered copies in a
temporary directory, never alters the authoritative wheel.
"""

from __future__ import annotations

from pathlib import Path
from sys import argv, exit
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from verify_built_wheel import verify_wheel


def altered_copy(original: Path, output: Path, change: str) -> None:
    with ZipFile(original) as source, ZipFile(output, "w") as target:
        for item in source.infolist():
            name = item.filename
            if change == "missing_license" and name.endswith(".dist-info/licenses/LICENSE"):
                continue
            data = source.read(name)
            if change == "alter_payload" and name == "scrapling/__init__.py":
                data += b"\n# tampered without updating RECORD\n"
            target.writestr(item, data)


def main(original: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    verify_wheel(original, root)
    with TemporaryDirectory(prefix="goreecloud-wheel-negatives-") as directory:
        for kind in ("missing_license", "alter_payload"):
            candidate = Path(directory) / f"{kind}.whl"
            altered_copy(original, candidate, kind)
            try:
                verify_wheel(candidate, root)
            except ValueError:
                continue
            raise AssertionError(f"Tampered {kind} wheel was incorrectly accepted")
    print("Wheel integrity negative tests passed: omitted license and altered payload rejected")


if __name__ == "__main__":
    if len(argv) != 2:
        exit("Usage: python scripts/test_verify_built_wheel.py PATH_TO_WHEEL")
    main(Path(argv[1]))
