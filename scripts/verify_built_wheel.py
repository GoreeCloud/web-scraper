"""Validate a built GoreeCloud Web Scraper wheel using only the Python standard library.

This confirms archive and attribution integrity in the local build. It is not a
dependency-license audit, signature verification, or third-party attestation.
Requires Python >=3.11 (CI uses 3.12); the package itself supports Python 3.10.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
from configparser import ConfigParser
from csv import reader
from email.parser import Parser
from hashlib import sha256
from io import StringIO
from pathlib import Path, PurePosixPath
from sys import argv, exit
from tomllib import loads as parse_toml
from zipfile import ZipFile


def verify_wheel(path: Path, root: Path) -> None:
    project = parse_toml((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    normalized = project["name"].replace("-", "_")
    version = project["version"]
    info_prefix = f"{normalized}-{version}.dist-info/"
    scripts = project["scripts"]

    with ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError("Wheel contains duplicate archive names")
        for item in infos:
            name = item.filename
            parts = PurePosixPath(name).parts
            if not name or name.startswith("/") or ".." in parts or "\\" in name:
                raise ValueError(f"Unsafe wheel archive path: {name!r}")
            mode = (item.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f"Wheel contains an unreviewed symlink: {name!r}")
        if archive.testzip() is not None:
            raise ValueError("Wheel failed internal ZIP CRC validation")

        required = {
            info_prefix + "METADATA",
            info_prefix + "entry_points.txt",
            info_prefix + "licenses/LICENSE",
            info_prefix + "RECORD",
            "scrapling/__init__.py",
            "goreecloud_web_scraper/__init__.py",
        }
        missing = required.difference(names)
        if missing:
            raise ValueError(f"Wheel is missing required attribution or API entries: {sorted(missing)}")

        bundled_license = archive.read(info_prefix + "licenses/LICENSE")
        original_license = (root / "LICENSE").read_bytes()
        if bundled_license != original_license:
            raise ValueError("Bundled BSD-3-Clause license differs from reviewed source")

        metadata = Parser().parsestr(archive.read(info_prefix + "METADATA").decode("utf-8"))
        if metadata.get("Name", "").lower().replace("_", "-") != project["name"]:
            raise ValueError("Unexpected wheel distribution name")
        if metadata.get("Version") != version:
            raise ValueError("Unexpected wheel version")
        if not metadata.get_all("License-File") or "LICENSE" not in metadata.get_all("License-File"):
            raise ValueError("Wheel is missing explicit license metadata")
        if "D4Vinci/Scrapling" not in str(metadata):
            raise ValueError("Wheel omits upstream attribution in metadata/README")

        entrypoints = ConfigParser()
        entrypoints.read_string(archive.read(info_prefix + "entry_points.txt").decode("utf-8"))
        if not entrypoints.has_section("console_scripts"):
            raise ValueError("Missing console_scripts entry points")
        for command, implementation in scripts.items():
            if entrypoints.get("console_scripts", command, fallback=None) != implementation:
                raise ValueError(f"Missing or incorrect CLI alias: {command}")

        record = list(reader(StringIO(archive.read(info_prefix + "RECORD").decode("utf-8"))))
        record_names = [fields[0] for fields in record]
        if len(record_names) != len(set(record_names)) or set(record_names) != set(names):
            raise ValueError("Wheel RECORD does not cover the exact contents")
        for fields in record:
            if len(fields) != 3:
                raise ValueError("Wheel RECORD must contain exactly three fields per entry")
            name, recorded_hash, recorded_size = fields
            if name == info_prefix + "RECORD":
                if recorded_hash or recorded_size:
                    raise ValueError("Wheel RECORD must leave its own hash and size empty")
                continue
            content = archive.read(name)
            digest = urlsafe_b64encode(sha256(content).digest()).decode("ascii").rstrip("=")
            if recorded_hash != "sha256=" + digest or recorded_size != str(len(content)):
                raise ValueError(f"Wheel RECORD digest or length does not match {name}")

    print(f"Wheel archive, BSD license, attribution, aliases and RECORD verified: {path.name}")


if __name__ == "__main__":
    if len(argv) != 2:
        exit("Usage: python scripts/verify_built_wheel.py PATH_TO_WHEEL")
    try:
        verify_wheel(Path(argv[1]), Path(__file__).resolve().parents[1])
    except (OSError, KeyError, ValueError) as exc:
        exit(f"Wheel integrity verification failed: {exc}")
