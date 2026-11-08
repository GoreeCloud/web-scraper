"""Build a deterministic *metadata-only* CycloneDX v1.5 development snapshot.

Scope is the Python distributions installed in the invoking interpreter.
This is NOT an independently verified dependency closure, complete license
review, reproducible lockfile, or production/software-release SBOM. It never
contacts a package index, imports the listed packages, or reads their files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from importlib import metadata
from pathlib import Path
from urllib.parse import quote


def normalized_name(value: str) -> str:
    name = re.sub(r"[-_.]+", "-", value).lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name):
        raise ValueError("Invalid installed distribution name")
    return name


def component(distribution: metadata.Distribution) -> dict:
    package = distribution.metadata
    name = package.get("Name")
    version = package.get("Version")
    if not name or not version:
        raise ValueError("Installed distribution lacks name or version")
    canonical = normalized_name(name)
    # Escape versions instead of assuming they are safely URL-shaped.
    purl = f"pkg:pypi/{canonical}@{quote(version, safe='')}"
    result = {
        "type": "library",
        "name": name,
        "version": version,
        "bom-ref": purl,
        "purl": purl,
    }
    expressions = package.get_all("License-Expression", [])
    classifiers = [
        value.removeprefix("License :: ").strip()
        for value in package.get_all("Classifier", [])
        if value.startswith("License :: ")
    ]
    legacy = package.get("License")
    if expressions:
        # Claim made by installed metadata, NOT independently SPDX-validated.
        result["licenses"] = [{"expression": expressions[0]}]
        source = "License-Expression"
    elif classifiers:
        # Keep the classifier text, never infer an SPDX identifier.
        result["licenses"] = [{"license": {"name": classifiers[0]}}]
        source = "Classifier"
    else:
        source = "unclassified"
    properties = [
        {"name": "goreecloud:license-evidence-source", "value": source},
        {"name": "goreecloud:legacy-license-field-present", "value": str(legacy is not None).lower()},
    ]
    if legacy:
        properties.append({
            "name": "goreecloud:legacy-license-field-sha256",
            "value": hashlib.sha256(legacy.encode("utf-8")).hexdigest(),
        })
    result["properties"] = properties
    return result


def build_bom(distributions: list[metadata.Distribution], root_distribution: str) -> dict:
    components = [component(d) for d in distributions]
    refs = [c["bom-ref"] for c in components]
    if len(refs) != len(set(refs)):
        raise ValueError("Duplicate installed Python package coordinates")
    components.sort(key=lambda c: (normalized_name(c["name"]), c["version"]))
    root = normalized_name(root_distribution)
    matches = [item for item in components if normalized_name(item["name"]) == root]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one installed root package: {root}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": matches[0]["name"],
                "version": matches[0]["version"],
            },
            "properties": [
                {"name": "goreecloud:inventory-scope", "value": "all installed Python distributions in this interpreter"},
                {"name": "goreecloud:license-audit-status", "value": "UNREVIEWED: metadata labels only"},
                {"name": "goreecloud:dependency-graph-status", "value": "not-resolved: flat installed environment"},
            ],
        },
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bom = build_bom(
        list(metadata.distributions()),
        root_distribution="goreecloud-web-scraper",
    )
    payload = (json.dumps(bom, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    args.output.write_bytes(payload)
    unknowns = sum(not item.get("licenses") for item in bom["components"])
    print(
        f"Development CycloneDX metadata inventory: {len(bom['components'])} installed distributions; "
        f"{unknowns} lacking License-Expression/classifier metadata; "
        f"SHA-256 {hashlib.sha256(payload).hexdigest()}"
    )
    print("Scope: installed Python environment only; license metadata unverified, dependency graph unresolved.")


if __name__ == "__main__":
    main()
