"""Keep the LintLang consumer pin outside routine dependency automation."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "lintlang.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
# Reviewed release pair for the workflow's intentional compatibility probe.
# Update this only in a dedicated semantic review of LintLang behavior.
PINNED_LINTLANG_REF = ("6aace2a175483757c64d7aa2105346d1cc34b857", "v0.7.1")
UNAPPROVED_LINTLANG_REF = ("c0cab00048220286858f227aaf4b13cc043f718b", "v0.8.0")


def _lintlang_ref(workflow: str) -> tuple[str, str]:
    match = re.search(
        r"uses:\s+hermes-labs-ai/lintlang@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)",
        workflow,
    )
    assert match, "LintLang must use a full immutable SHA with a version comment"
    return match.groups()


def _assert_approved_held_pin(workflow: str) -> None:
    ref = _lintlang_ref(workflow)
    assert ref != UNAPPROVED_LINTLANG_REF, "LintLang must remain on the approved compatibility probe"
    assert ref == PINNED_LINTLANG_REF, "LintLang must use the approved SHA and version pair"


def test_lintlang_pin_is_immutable_and_deliberately_held() -> None:
    _assert_approved_held_pin(WORKFLOW.read_text())


@pytest.mark.parametrize(
    "replacement",
    [
        UNAPPROVED_LINTLANG_REF,
        ("0" * 40, PINNED_LINTLANG_REF[1]),
        (PINNED_LINTLANG_REF[0], UNAPPROVED_LINTLANG_REF[1]),
    ],
)
def test_unapproved_pin_is_a_failing_control(replacement: tuple[str, str]) -> None:
    """Well-formed pins must still satisfy the approved compatibility policy."""
    workflow = WORKFLOW.read_text()
    sha, version = _lintlang_ref(WORKFLOW.read_text())
    unapproved = workflow.replace(f"@{sha} # {version}", f"@{replacement[0]} # {replacement[1]}")
    assert _lintlang_ref(unapproved) == replacement

    with pytest.raises(AssertionError, match="approved compatibility probe|approved SHA"):
        _assert_approved_held_pin(unapproved)


def test_dependabot_monitors_actions_except_the_held_lintlang_probe() -> None:
    config = yaml.safe_load(DEPENDABOT.read_text())

    github_actions = [
        update
        for update in config["updates"]
        if update["package-ecosystem"] == "github-actions"
    ]
    assert len(github_actions) == 1
    update = github_actions[0]
    assert update["directory"] == "/"
    assert update["schedule"] == {"interval": "weekly"}
    assert update["open-pull-requests-limit"] == 5
    assert update["groups"] == {"github-actions": {"patterns": ["*"]}}
    assert update["ignore"] == [{"dependency-name": "hermes-labs-ai/lintlang"}]


def test_tag_ref_is_a_failing_control() -> None:
    """A tag would defeat the immutable-pin contract and must be rejected."""

    workflow = WORKFLOW.read_text()
    sha, version = _lintlang_ref(workflow)
    unpinned = workflow.replace(f"@{sha}", f"@{version}")

    with pytest.raises(AssertionError, match="full immutable SHA"):
        _lintlang_ref(unpinned)
