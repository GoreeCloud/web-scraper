"""Read-only, bounded evidence of license files shipped in installed Python distributions.

This is NOT a license-compliance verdict, a dependency closure, or a production
SBOM. Only paths declared in installed package file manifests are considered.
It does not import inspected packages, execute scripts, contact a registry,
copy license bodies, inspect packages outside the invoking interpreter or
infer SPDX permissions from arbitrary license text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from importlib import metadata
from pathlib import Path, PurePosixPath

from generate_dependency_inventory import normalized_name


MAX_LICENSE_FILE_BYTES = 1024 * 1024
MAX_LICENSE_FILES_PER_DISTRIBUTION = 64
_LICENSE_BASENAME = re.compile(
    r"(?:licen[sc]e|copying|notice|third[-_.]?party[-_.]?notices?)(?:[-_.].*)?",
    re.IGNORECASE,
)


def _license_manifest_path(entry: object) -> str | None:
    raw = str(entry)
    # Wheel RECORD may legitimately list ../../../bin/console-script outside
    # site-packages. Ignore non-license manifest entries; never inspect them.
    # But a license-looking path must pass strict confinement validation.
    if not _LICENSE_BASENAME.fullmatch(PurePosixPath(raw.replace("\\", "/")).name):
        return None
    if not raw or "\\" in raw:
        raise ValueError("Unsafe installed package manifest file path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {".", "..", ""} for part in raw.split("/")):
        raise ValueError("Unsafe installed package manifest file path")
    return str(path)


def _read_license_artifact(distribution: metadata.Distribution, relative: str) -> dict:
    base = Path(distribution.locate_file("")).resolve(strict=True)
    candidate = Path(distribution.locate_file(relative))
    # The path and all of its resolved parents must stay inside the installed
    # distribution location. Reject symlinks on the final component.
    if candidate.is_symlink():
        raise ValueError("License artifact is a symlink")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(base):
        raise ValueError("License artifact escapes installed distribution root")
    expected = resolved.stat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(candidate, flags)
    with os.fdopen(fd, "rb") as source:
        details = os.fstat(source.fileno())
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("License artifact is not a regular file")
        if (details.st_dev, details.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError("License artifact identity changed during opening")
        if details.st_size > MAX_LICENSE_FILE_BYTES:
            raise ValueError("License artifact exceeds the 1 MiB inspection ceiling")
        body = source.read(MAX_LICENSE_FILE_BYTES + 1)
        if len(body) > MAX_LICENSE_FILE_BYTES:
            raise ValueError("License artifact exceeds the 1 MiB inspection ceiling")
    return {
        "path": relative,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def evidence(distribution: metadata.Distribution) -> dict:
    package = distribution.metadata
    name, version = package.get("Name"), package.get("Version")
    if not name or not version:
        raise ValueError("Installed distribution lacks name or version")
    canonical = normalized_name(name)
    paths = [
        relative
        for entry in (distribution.files or ())
        if (relative := _license_manifest_path(entry)) is not None
    ]
    if len(paths) != len(set(paths)):
        raise ValueError("Duplicated license artifact path in package manifest")
    if len(paths) > MAX_LICENSE_FILES_PER_DISTRIBUTION:
        raise ValueError("Too many license artifacts for bounded inspection")
    files = [_read_license_artifact(distribution, path) for path in sorted(paths)]
    return {
        "name": name,
        "version": version,
        "normalized_name": canonical,
        "files": files,
        "has_recorded_license_artifact": bool(files),
    }


def build_evidence(distributions: list[metadata.Distribution], root_distribution: str) -> dict:
    records = [evidence(dist) for dist in distributions]
    references = [(item["normalized_name"], item["version"]) for item in records]
    if len(set(references)) != len(references):
        raise ValueError("Duplicate installed distribution coordinates")
    records.sort(key=lambda item: (item["normalized_name"], item["version"]))
    root = normalized_name(root_distribution)
    if sum(item["normalized_name"] == root for item in records) != 1:
        raise ValueError(f"Expected exactly one installed root distribution: {root}")
    return {
        "format": "GoreeCloud installed Python license-artifact evidence v1",
        "status": "UNREVIEWED: file presence, size and SHA-256 are not legal clearance",
        "scope": "installed distributions in this interpreter only",
        "root_distribution": root,
        "records": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_evidence(
        list(metadata.distributions()),
        root_distribution="goreecloud-web-scraper",
    )
    data = (json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
    args.output.write_bytes(data)
    missing = sum(not item["files"] for item in report["records"])
    inspected = sum(len(item["files"]) for item in report["records"])
    print(
        f"Development installed-license artifacts: {len(report['records'])} distributions; "
        f"{inspected} file hashes; {missing} packages without recorded license artifacts; "
        f"SHA-256 {hashlib.sha256(data).hexdigest()}"
    )
    print("Review status: UNREVIEWED, not full dependency/source license clearance.")


if __name__ == "__main__":
    main()
