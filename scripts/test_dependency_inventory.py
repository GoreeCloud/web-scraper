"""Offline regression checks for the metadata-only dependency inventory tool."""

from __future__ import annotations

import json
import unittest
from email.message import Message

from generate_dependency_inventory import build_bom, component, normalized_name


class FakeDistribution:
    def __init__(
        self,
        name: str,
        version: str,
        *,
        expression: str | None = None,
        license_text: str | None = None,
        license_classifiers: tuple[str, ...] = (),
    ):
        self.metadata = Message()
        self.metadata["Name"] = name
        self.metadata["Version"] = version
        if expression:
            self.metadata["License-Expression"] = expression
        if license_text:
            self.metadata["License"] = license_text
        for value in license_classifiers:
            self.metadata["Classifier"] = f"License :: {value}"


class InventoryTests(unittest.TestCase):
    def test_installed_packages_are_sorted_and_deterministic(self):
        packages = [
            FakeDistribution("ZZZ_tool", "2.0", expression="Apache-2.0"),
            FakeDistribution("goreecloud-web-scraper", "0.5.1", license_text="BSD text"),
            FakeDistribution("a.Pkg", "1.3", license_classifiers=("OSI Approved :: MIT License",)),
        ]
        left = build_bom(packages, "goreecloud-web-scraper")
        right = build_bom(list(reversed(packages)), "goreecloud-web-scraper")
        self.assertEqual(
            json.dumps(left, sort_keys=True),
            json.dumps(right, sort_keys=True),
        )
        self.assertEqual(left["bomFormat"], "CycloneDX")
        self.assertEqual(left["specVersion"], "1.5")
        self.assertEqual([x["purl"] for x in left["components"]], [
            "pkg:pypi/a-pkg@1.3",
            "pkg:pypi/goreecloud-web-scraper@0.5.1",
            "pkg:pypi/zzz-tool@2.0",
        ])

    def test_license_sources_are_evidence_not_claimed_authorization(self):
        explicit = component(FakeDistribution("pkg", "1", expression="MIT"))
        self.assertEqual(explicit["licenses"], [{"expression": "MIT"}])
        legacy = component(FakeDistribution("pkg", "1", license_text="Long legal text"))
        self.assertNotIn("licenses", legacy)
        serialized = json.dumps(legacy)
        self.assertNotIn("Long legal text", serialized)
        self.assertIn("legacy-license-field-sha256", serialized)
        classified = component(FakeDistribution(
            "pkg", "1", license_classifiers=("OSI Approved :: MIT License",)
        ))
        self.assertEqual(classified["licenses"], [
            {"license": {"name": "OSI Approved :: MIT License"}}
        ])
        empty = component(FakeDistribution("pkg", "1"))
        self.assertNotIn("licenses", empty)

    def test_invalid_and_duplicate_coordinates_fail_closed(self):
        with self.assertRaises(ValueError):
            normalized_name("space separated")
        with self.assertRaises(ValueError):
            build_bom([FakeDistribution("other", "1")], "goreecloud-web-scraper")
        with self.assertRaises(ValueError):
            build_bom([
                FakeDistribution("goreecloud-web-scraper", "1"),
                FakeDistribution("GoreeCloud.Web_Scraper", "1"),
            ], "goreecloud-web-scraper")

    def test_no_system_probing_or_network_indicators_in_output(self):
        bom = build_bom([FakeDistribution("goreecloud-web-scraper", "0.5.1")], "goreecloud-web-scraper")
        serialized = json.dumps(bom)
        self.assertNotIn("HOME", serialized)
        self.assertNotIn("username", serialized)
        self.assertIn("not-resolved", serialized)
        self.assertIn("UNREVIEWED", serialized)


if __name__ == "__main__":
    unittest.main()
