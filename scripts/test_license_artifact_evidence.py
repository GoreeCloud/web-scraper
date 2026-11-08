"""Offline safety and determinism regressions for installed license artifact evidence."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from generate_license_artifact_evidence import (
    MAX_LICENSE_FILE_BYTES,
    build_evidence,
    evidence,
)


class FakeDistribution:
    def __init__(self, root: Path, name: str, version: str, paths: list[str]):
        self.root = root
        self.metadata = Message()
        self.metadata["Name"] = name
        self.metadata["Version"] = version
        self.files = list(paths)

    def locate_file(self, relative):
        return self.root / relative


class ArtifactEvidenceTests(unittest.TestCase):
    def test_real_bytes_and_manifest_order_without_copying_license_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "licenses").mkdir()
            protected_text = b"Example vendor license; private test content"
            (root / "licenses" / "LICENSE.txt").write_bytes(protected_text)
            (root / "NOTICE").write_bytes(b"Notices")
            (root / "credentials.txt").write_text("not a license", encoding="utf-8")
            main = FakeDistribution(
                root, "goreecloud-web-scraper", "0.5.1",
                ["credentials.txt", "licenses/LICENSE.txt", "NOTICE"],
            )
            other = FakeDistribution(root, "other.Pkg", "1.0", [])
            first = build_evidence([main, other], "goreecloud-web-scraper")
            second = build_evidence([other, main], "goreecloud-web-scraper")
            self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
            data = json.dumps(first)
            self.assertNotIn(str(root), data)
            self.assertNotIn(protected_text.decode(), data)
            self.assertNotIn("credentials.txt", data)
            entries = first["records"][0]["files"]
            self.assertEqual([item["path"] for item in entries], ["NOTICE", "licenses/LICENSE.txt"])
            self.assertEqual(entries[1]["sha256"], hashlib.sha256(protected_text).hexdigest())
            self.assertEqual(entries[1]["bytes"], len(protected_text))
            self.assertFalse(first["records"][1]["has_recorded_license_artifact"])
            self.assertIn("UNREVIEWED", data)

    def test_bad_package_coordinates_and_duplicate_paths_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "LICENSE").write_text("test")
            root_dist = FakeDistribution(root, "goreecloud-web-scraper", "0.5.1", ["LICENSE"])
            with self.assertRaisesRegex(ValueError, "root distribution"):
                build_evidence([FakeDistribution(root, "other", "1", [])], "goreecloud-web-scraper")
            with self.assertRaisesRegex(ValueError, "Duplicate installed distribution"):
                build_evidence([root_dist, root_dist], "goreecloud-web-scraper")
            with self.assertRaisesRegex(ValueError, "Duplicated license artifact"):
                evidence(FakeDistribution(root, "a", "1", ["LICENSE", "LICENSE"]))

    def test_path_traversal_and_manifest_absolute_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for unsafe in ("../outside/LICENSE", "/etc/LICENSE", "./LICENSE", "a//LICENSE", "a\\LICENSE"):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaisesRegex(ValueError, "Unsafe"):
                        evidence(FakeDistribution(root, "goreecloud-web-scraper", "1", [unsafe]))

    def test_oversized_license_content_rejected_before_allocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "LICENSE").write_bytes(b"x" * (MAX_LICENSE_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                evidence(FakeDistribution(root, "goreecloud-web-scraper", "1", ["LICENSE"]))

    def test_symlink_escape_or_final_component_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root.parent / (root.name + "-outside-artifact")
            outside.write_text("test license", encoding="utf-8")
            try:
                (root / "LICENSE").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    evidence(FakeDistribution(root, "goreecloud-web-scraper", "1", ["LICENSE"]))
            finally:
                outside.unlink(missing_ok=True)

    def test_missing_manifest_is_evidence_gap_not_compliance_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dist = FakeDistribution(root, "goreecloud-web-scraper", "1", [])
            self.assertEqual(evidence(dist)["files"], [])
            self.assertFalse(evidence(dist)["has_recorded_license_artifact"])


if __name__ == "__main__":
    unittest.main()
