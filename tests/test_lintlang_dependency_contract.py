"""Keep the LintLang consumer pin and its Dependabot path reviewable."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "lintlang.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
CURRENT_LINTLANG_SHA = "58e66871531eb585869336189d07b4334e963a5f"  # v0.6.0
PINNED_LINTLANG_SHA = "f89c3b0b8986fad162859dca052a8d5fe227eede"  # v0.5.3


def _lintlang_ref(workflow: str) -> tuple[str, str]:
    match = re.search(
        r"uses:\s+hermes-labs-ai/lintlang@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)",
        workflow,
    )
    assert match, "LintLang must use a full immutable SHA with a version comment"
    return match.groups()


def test_lintlang_pin_is_immutable_and_deliberately_stale() -> None:
    sha, version = _lintlang_ref(WORKFLOW.read_text())

    assert sha == PINNED_LINTLANG_SHA
    assert version == "v0.5.3"
    assert sha != CURRENT_LINTLANG_SHA


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

    unpinned = WORKFLOW.read_text().replace(f"@{PINNED_LINTLANG_SHA}", "@v0.6.0")

    with pytest.raises(AssertionError, match="full immutable SHA"):
        _lintlang_ref(unpinned)
