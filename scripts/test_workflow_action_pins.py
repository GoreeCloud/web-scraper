"""Offline tests for GitHub Actions commit pin policy."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_workflow_action_pins import (
    VERIFIED_ACTION_SHAS,
    check_workflows,
    validate_workflow_content,
)


class PinSafetyTests(unittest.TestCase):
    def test_exact_verified_pins_and_local_relative_actions_accepted(self):
        source = (
            "jobs:\n"
            f"  - uses: actions/checkout@{VERIFIED_ACTION_SHAS['actions/checkout']} # v6\n"
            f"  uses: actions/setup-python@{VERIFIED_ACTION_SHAS['actions/setup-python']}\n"
            "  - uses: ./.github/actions/local-build\n"
        )
        count, errors = validate_workflow_content("ci.yml", source)
        self.assertEqual(count, 3)
        self.assertEqual(errors, [])

    def test_unpinned_tags_branch_refs_and_unknown_actions_rejected(self):
        for value in (
            "actions/checkout@v6",
            "actions/setup-python@main",
            "actions/checkout@0000000000000000000000000000000000000000",
            "external/unknown@1111111111111111111111111111111111111111",
            "docker://alpine:latest",
            "../untrusted/action",
            "actions/checkout",
        ):
            with self.subTest(value=value):
                count, errors = validate_workflow_content("ci.yml", "  - uses: " + value + "\n")
                self.assertEqual(count, 1)
                self.assertEqual(len(errors), 1)
                self.assertIn("unapproved or mutable", errors[0])
                self.assertNotIn(value, errors[0])  # No arbitrary source echo.

    def test_active_workflow_directory_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            count, errors = check_workflows(root)
            self.assertEqual(count, 0)
            self.assertTrue(errors)
            (root / "a.yml").write_text(
                f"  - uses: actions/checkout@{VERIFIED_ACTION_SHAS['actions/checkout']}\n",
                encoding="utf-8",
            )
            (root / "b.yaml").write_text("  - uses: actions/setup-python@v6\n", encoding="utf-8")
            count, errors = check_workflows(root)
            self.assertEqual(count, 2)
            self.assertEqual(len(errors), 1)

    def test_comment_and_script_strings_do_not_count_as_action_refs(self):
        source = (
            "  # - uses: actions/checkout@v6\n"
            "  run: echo 'uses: actions/checkout@v6'\n"
        )
        count, errors = validate_workflow_content("ci.yml", source)
        self.assertEqual(count, 0)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
