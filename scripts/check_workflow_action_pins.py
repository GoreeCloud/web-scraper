"""Fail closed on unreviewed or moving GitHub Actions references.

This deliberately narrow, standard-library check enforces the commit pins
verified for the repository's active workflow. It is NOT a YAML parser or a
security review of the upstream GitHub Actions implementation.
"""

from __future__ import annotations

import re
from pathlib import Path


# GitHub Git ref API, refs/tags/v6, resolved to commit SHA on 2026-11-08.
VERIFIED_ACTION_SHAS = {
    "actions/checkout": "d23441a48e516b6c34aea4fa41551a30e30af803",
    "actions/setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
}
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")
LOCAL_REF = re.compile(r"^\./(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$")


def validate_workflow_content(name: str, source: str) -> tuple[int, list[str]]:
    count = 0
    errors: list[str] = []
    for number, line in enumerate(source.splitlines(), 1):
        match = USES_LINE.match(line)
        if not match:
            continue
        count += 1
        value = match.group(1)
        if LOCAL_REF.fullmatch(value):
            continue
        action, separator, revision = value.rpartition("@")
        approved = VERIFIED_ACTION_SHAS.get(action)
        if not separator or approved is None or revision != approved:
            errors.append(
                f"{name}:{number}: unapproved or mutable action reference "
                "(review source and update the exact trusted commit pin)"
            )
    return count, errors


def check_workflows(root: Path) -> tuple[int, list[str]]:
    workflows = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    if not workflows:
        return 0, ["No active GitHub Actions workflow files were found"]
    count = 0
    errors = []
    for file in workflows:
        uses, problems = validate_workflow_content(file.name, file.read_text(encoding="utf-8"))
        count += uses
        errors.extend(problems)
    return count, errors


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    count, errors = check_workflows(root)
    for problem in errors:
        print(problem)
    if errors:
        raise SystemExit(f"FAIL: {len(errors)} unreviewed GitHub Actions reference(s)")
    print(f"Verified {count} immutable, explicitly approved GitHub Actions reference(s)")


if __name__ == "__main__":
    main()
