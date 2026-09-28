"""Keep the LintLang consumer pin and its Dependabot path reviewable."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "lintlang.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"


def _lintlang_ref(workflow: str) -> tuple[str, str]:
    match = re.search(
        r"uses:\s+hermes-labs-ai/lintlang@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)",
        workflow,
    )
    assert match, "LintLang must use a full immutable SHA with a version comment"
    return match.groups()


def test_lintlang_pin_is_immutable_and_versioned() -> None:
    sha, version = _lintlang_ref(WORKFLOW.read_text())

    assert len(sha) == 40
    assert version.startswith("v")


def test_dependabot_monitors_github_actions() -> None:
    config = yaml.safe_load(DEPENDABOT.read_text())

    github_actions = [
        update
        for update in config["updates"]
        if update["package-ecosystem"] == "github-actions"
    ]
    assert github_actions == [
        {
            "package-ecosystem": "github-actions",
            "directory": "/",
            "schedule": {"interval": "weekly"},
            "open-pull-requests-limit": 5,
            "groups": {"github-actions": {"patterns": ["*"]}},
        }
    ]


def test_tag_ref_is_a_failing_control() -> None:
    """A tag would defeat the immutable-pin contract and must be rejected."""

    workflow = WORKFLOW.read_text()
    sha, version = _lintlang_ref(workflow)
    unpinned = workflow.replace(f"@{sha}", f"@{version}")

    with pytest.raises(AssertionError, match="full immutable SHA"):
        _lintlang_ref(unpinned)
