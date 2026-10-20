"""Keep the LintLang consumer pin outside routine dependency automation."""

import re
import subprocess
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
    references = []

    def visit(node):
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if key.value == "uses" and isinstance(value, yaml.ScalarNode):
                    action, _, ref = value.value.partition("@")
                    if action.casefold() == "hermes-labs-ai/lintlang" or action.casefold().startswith(
                        "hermes-labs-ai/lintlang/"
                    ):
                        references.append((action, ref, value.start_mark.line))
                visit(value)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                visit(value)

    for document in yaml.compose_all(workflow):
        visit(document)
    assert len(references) == 1, "Exactly one LintLang action reference is required"
    action, ref, line = references[0]
    assert action == "hermes-labs-ai/lintlang" and re.fullmatch(r"[0-9a-f]{40}", ref), (
        "LintLang must use a full immutable SHA with a version comment"
    )
    version = re.search(r"#\s+(v\d+\.\d+\.\d+)\s*$", workflow.splitlines()[line])
    assert version, "LintLang must use a full immutable SHA with a version comment"
    return ref, version[1]


def _assert_approved_held_pin(workflow: str) -> None:
    ref = _lintlang_ref(workflow)
    assert ref != UNAPPROVED_LINTLANG_REF, "LintLang must remain on the approved compatibility probe"
    assert ref == PINNED_LINTLANG_REF, "LintLang must use the approved SHA and version pair"



def _action_documents(root: Path) -> str:
    # Git's index includes forced-tracked manifests even under .venv/node_modules,
    # while excluding unrelated ignored install output. Standalone fixtures have
    # no repository, so discover their documents directly.
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard",
         "-z", "--", "*.yml", "*.yaml"], capture_output=True, check=False,
    )
    if result.returncode == 0:
        paths = {root / path.decode() for path in result.stdout.split(b"\0") if path}
    else:
        paths = {path for path in root.rglob("*.y*ml") if ".git" not in path.relative_to(root).parts}
    documents = {
        path for path in paths
        if path.name in {"action.yml", "action.yaml"}
        or path.parent == root / ".github/workflows"
    }
    return "\n---\n".join(path.read_text(encoding="utf-8") for path in sorted(documents))


def test_lintlang_pin_is_immutable_and_deliberately_held() -> None:
    _assert_approved_held_pin(_action_documents(ROOT))


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


@pytest.mark.parametrize("reference", [
    "hermes-labs-ai/lintlang@" + UNAPPROVED_LINTLANG_REF[0],
    "hermes-labs-ai/lintlang@v0.8.0",
    "hermes-labs-ai/lintlang@" + PINNED_LINTLANG_REF[0],
    "Hermes-Labs-AI/LintLang@v0.8.0",
])
@pytest.mark.parametrize("another_workflow", [False, True])
def test_additional_lintlang_invocation_is_a_failing_control(reference, another_workflow):
    workflow = WORKFLOW.read_text()
    extra = f'      - uses: "{reference}" # v0.8.0\n'
    if another_workflow:
        workflow += "\n---\njobs:\n  other:\n    steps:\n" + extra
    else:
        workflow += extra
    with pytest.raises(AssertionError, match="Exactly one"):
        _assert_approved_held_pin(workflow)


@pytest.mark.parametrize("manifest", ["action.yml", "action.yaml"])
@pytest.mark.parametrize("directory", ["actions/probe", "build/probe", "dist/probe", "node_modules/probe", ".venv/probe"])
def test_local_composite_cannot_hide_an_additional_lintlang_reference(tmp_path, manifest, directory):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    workflow = WORKFLOW.read_text() + f"      - uses: ./{directory}\n"
    (workflows / "probe.yml").write_text(workflow)
    local_action = tmp_path / directory
    local_action.mkdir(parents=True)
    (local_action / manifest).write_text(
        "runs:\n  using: composite\n  steps:\n"
        f"    - uses: hermes-labs-ai/lintlang@{UNAPPROVED_LINTLANG_REF[0]} # v0.8.0\n"
    )
    with pytest.raises(AssertionError, match="Exactly one"):
        _assert_approved_held_pin(_action_documents(tmp_path))



@pytest.mark.parametrize("directory", [".venv/probe", "node_modules/probe", "build/probe", "dist/probe"])
def test_tracked_composite_is_scanned_even_inside_ignored_directory(tmp_path, directory):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(directory.split("/")[0] + "/\n")
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "probe.yml").write_text(WORKFLOW.read_text() + f"      - uses: ./{directory}\n")
    action = tmp_path / directory / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text("runs:\n  using: composite\n  steps:\n"
                      f"    - uses: hermes-labs-ai/lintlang@{UNAPPROVED_LINTLANG_REF[0]} # v0.8.0\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-f", str(action)], check=True)
    with pytest.raises(AssertionError, match="Exactly one"):
        _assert_approved_held_pin(_action_documents(tmp_path))


def test_unrelated_ignored_environment_manifest_does_not_break_repository_contract(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".venv/\n")
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "probe.yml").write_text(WORKFLOW.read_text())
    ignored = tmp_path / ".venv/third-party/action.yml"
    ignored.parent.mkdir(parents=True)
    ignored.write_bytes(b"\xffunrelated install template, not executable repository content")
    _assert_approved_held_pin(_action_documents(tmp_path))
