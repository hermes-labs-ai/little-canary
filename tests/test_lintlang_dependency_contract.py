"""Keep the LintLang consumer pin and its Dependabot path reviewable."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "lintlang.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
# Reviewed release pair for the workflow's intentional one-release-behind policy.
# Update these together when approving a new Dependabot proposal.
PINNED_LINTLANG_REF = ("6aace2a175483757c64d7aa2105346d1cc34b857", "v0.7.1")
CURRENT_LINTLANG_REF = ("c0cab00048220286858f227aaf4b13cc043f718b", "v0.8.0")


def _lintlang_ref(workflow: str) -> tuple[str, str]:
    match = re.search(
        r"uses:\s+hermes-labs-ai/lintlang@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)",
        workflow,
    )
    assert match, "LintLang must use a full immutable SHA with a version comment"
    return match.groups()


def _assert_approved_stale_pin(workflow: str) -> None:
    ref = _lintlang_ref(workflow)
    assert ref != CURRENT_LINTLANG_REF, "LintLang must remain intentionally one release behind"
    assert ref == PINNED_LINTLANG_REF, "LintLang must use the approved SHA and version pair"


def test_lintlang_pin_is_immutable_and_deliberately_stale() -> None:
    _assert_approved_stale_pin(WORKFLOW.read_text())


@pytest.mark.parametrize(
    "replacement",
    [
        CURRENT_LINTLANG_REF,
        ("0" * 40, PINNED_LINTLANG_REF[1]),
        (PINNED_LINTLANG_REF[0], CURRENT_LINTLANG_REF[1]),
    ],
)
def test_unapproved_pin_is_a_failing_control(replacement: tuple[str, str]) -> None:
    """Well-formed pins must still satisfy the approved stale-release policy."""
    workflow = WORKFLOW.read_text()
    sha, version = _lintlang_ref(WORKFLOW.read_text())
    unapproved = workflow.replace(f"@{sha} # {version}", f"@{replacement[0]} # {replacement[1]}")
    assert _lintlang_ref(unapproved) == replacement

    with pytest.raises(AssertionError, match="intentionally one release behind|approved SHA"):
        _assert_approved_stale_pin(unapproved)


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
