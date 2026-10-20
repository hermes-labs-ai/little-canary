"""Release-version and repository-identity consistency checks."""

import json
import re
from pathlib import Path

import pytest
import yaml
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from little_canary import __version__

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _match(relative_path: str, pattern: str) -> str:
    match = re.search(pattern, _read(relative_path), flags=re.MULTILINE)
    assert match is not None, f"{relative_path} does not match {pattern!r}"
    return match.group(1)


def _pinned_actions(steps: list[dict]) -> dict[str, str]:
    pinned = {}
    for step in steps:
        if "uses" not in step:
            continue
        action, separator, ref = step["uses"].partition("@")
        assert separator, f"{action} has no pinned ref"
        assert re.fullmatch(r"[0-9a-f]{40}", ref), f"{action} is not pinned to a full commit SHA"
        pinned[action] = ref
    return pinned


def test_release_version_surfaces_are_aligned():
    versions = {
        __version__,
        _match("pyproject.toml", r'^version = "([^"]+)"$'),
        _match("integrations/hermes-agent/plugin.yaml", r"^version: ([^\s]+)$"),
        _match("CITATION.cff", r'^version: "([^"]+)"$'),
        json.loads(_read(".zenodo.json"))["version"],
        json.loads(_read("codemeta.json"))["version"],
    }

    assert versions == {__version__}
    assert _match("CHANGELOG.md", r"^## \[([^\]]+)\] - ") == __version__


def test_current_release_metadata_uses_canonical_repository_identity():
    canonical_repository = "https://github.com/hermes-labs-ai/little-canary"
    current_metadata = {
        relative_path: _read(relative_path)
        for relative_path in (
            "pyproject.toml",
            "CITATION.cff",
            ".zenodo.json",
            "codemeta.json",
            "llms.txt",
        )
    }

    assert canonical_repository in current_metadata["pyproject.toml"]
    assert canonical_repository in current_metadata["CITATION.cff"]
    assert all("roli-lpci" not in text for text in current_metadata.values())


def test_codemeta_tracks_current_release_metadata():
    codemeta = json.loads(_read("codemeta.json"))
    canonical_repository = "https://github.com/hermes-labs-ai/little-canary"
    license_id = _match("pyproject.toml", r'^license = "([^"]+)"$')
    citation_orcid = _match("CITATION.cff", r'^    orcid: "([^"]+)"$')
    citation_given_name = _match("CITATION.cff", r'^    given-names: "([^"]+)"$')
    citation_family_name = _match("CITATION.cff", r'^  - family-names: "([^"]+)"$')
    citation_affiliation = _match("CITATION.cff", r'^    affiliation: "([^"]+)"$')
    maintainer_email = _match("pyproject.toml", r'^    \{name = "Hermes Labs", email = "([^"]+)"\},$')
    zenodo_creator = json.loads(_read(".zenodo.json"))["creators"][0]
    author = codemeta["author"]
    maintainer = codemeta["maintainer"]

    assert codemeta["@context"] == "https://w3id.org/codemeta/3.1"
    assert codemeta["@type"] == "SoftwareSourceCode"
    assert codemeta["version"] == __version__
    assert codemeta["identifier"] == "https://doi.org/10.5281/zenodo.21543681"
    assert codemeta["codeRepository"] == canonical_repository
    if f"## [{__version__}] - Unreleased" in _read("CHANGELOG.md"):
        assert "downloadUrl" not in codemeta
    else:
        assert codemeta["downloadUrl"] == f"https://pypi.org/project/little-canary/{__version__}/"
    assert codemeta["license"] == f"https://spdx.org/licenses/{license_id}"
    assert author["@id"] == maintainer["@id"] == citation_orcid
    assert zenodo_creator["orcid"] == citation_orcid.rsplit("/", maxsplit=1)[-1]
    assert author["givenName"] == maintainer["givenName"] == citation_given_name
    assert author["familyName"] == maintainer["familyName"] == citation_family_name
    assert zenodo_creator["name"] == f"{citation_family_name}, {citation_given_name}"
    assert author["affiliation"]["name"] == maintainer["affiliation"]["name"] == citation_affiliation
    assert zenodo_creator["affiliation"] == citation_affiliation
    assert maintainer["email"] == maintainer_email
    assert "dateModified" not in codemeta


def test_current_project_license_metadata_is_spdx_consistent():
    license_id = _match("pyproject.toml", r'^license = "([^\"]+)"$')
    assert license_id == "Apache-2.0"

    skill_license = _match(".agents/skills/little-canary/SKILL.md", r"^license: (\S+)$")
    citation_license = _match("CITATION.cff", r"^license: (\S+)$")
    zenodo_license = json.loads(_read(".zenodo.json"))["license"]
    codemeta_license = json.loads(_read("codemeta.json"))["license"]
    package_license = _match("little_canary/__init__.py", r"^License: (\S+)$")
    integration_package_license = _match(
        "integrations/hermes-agent/little_canary/__init__.py", r"^License: (\S+)$"
    )
    integration_manifest_license = _match("integrations/hermes-agent/plugin.yaml", r"^license: (\S+)$")
    agent_plugin_license = json.loads(_read("plugins/claude-code/.claude-plugin/plugin.json"))["license"]

    assert {
        license_id,
        skill_license,
        citation_license,
        zenodo_license,
        codemeta_license.rsplit("/", maxsplit=1)[-1],
        package_license,
        integration_package_license,
        integration_manifest_license,
        agent_plugin_license,
    } == {"Apache-2.0"}


def test_changelog_top_entry_tracks_the_current_version():
    headings = re.findall(r"^## \[([^\]]+)\] - (.+)$", _read("CHANGELOG.md"), flags=re.MULTILINE)

    assert headings, "CHANGELOG.md contains no release headings"
    top_version, top_status = headings[0]
    assert top_version == __version__
    assert top_status == "Unreleased" or re.fullmatch(r"\d{4}-\d{2}-\d{2}", top_status), top_status
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) for _, date in headings[1:])


def test_release_docs_do_not_assert_current_external_registry_state():
    for relative_path in ("CHANGELOG.md",):
        text = _read(relative_path)

        assert "currently publishes" not in text, relative_path
        assert "source candidate" not in text, relative_path
        assert "artifact exists" not in text, relative_path
        assert "Before publication" not in text, relative_path


def _assert_publish_privileges(workflow: str) -> None:
    parsed = yaml.safe_load(workflow)
    triggers = parsed.get("on", parsed.get(True))
    build = parsed["jobs"]["build"]
    publish = parsed["jobs"]["publish"]
    assert triggers["release"]["types"] == ["published"]
    assert build["permissions"] == {"contents": "read"}
    assert publish["permissions"] == {"contents": "read", "id-token": "write"}
    assert publish["needs"] == "build"
    commands = "\n".join(step.get("run", "") for step in build["steps"])
    assert 'test "${GITHUB_REF_NAME}" = "v${package_version}"' in commands
    assert "python -m build" in commands
    assert "python -m twine check dist/*" in commands
    build_actions = _pinned_actions(build["steps"])
    publish_actions = _pinned_actions(publish["steps"])
    assert "actions/upload-artifact" in build_actions
    assert {"actions/download-artifact", "pypa/gh-action-pypi-publish"} <= publish_actions.keys()


def test_publish_workflow_keeps_build_privileges_away_from_publishing():
    _assert_publish_privileges(_read(".github/workflows/publish.yml"))


@pytest.mark.parametrize("permission", ['id-token: write', '"id-token": "write"', "'id-token': 'write'"])
def test_build_oidc_permission_is_a_failing_control(permission):
    workflow = _read(".github/workflows/publish.yml").replace(
        "    permissions:\n      contents: read", f"    permissions:\n      {permission}\n      contents: read", 1
    )
    with pytest.raises(AssertionError):
        _assert_publish_privileges(workflow)


def _assert_requests_contract(project_text: str, requirements_text: str) -> None:
    project = tomllib.loads(project_text)["project"]
    project_requests = [
        req for value in project["dependencies"]
        if canonicalize_name((req := Requirement(value)).name) == "requests"
    ]
    requirements = [
        Requirement(line) for line in requirements_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    requirements_requests = [req for req in requirements if canonicalize_name(req.name) == "requests"]
    assert len(project_requests) == len(requirements_requests) == 2
    expected = {
        Marker('python_version < "3.10"'): "2.33",
        Marker('python_version >= "3.10"'): "3",
    }
    assert {req.marker for req in project_requests} == set(expected)
    # Requirement equality handles whitespace, case, specifier order and quote style.
    assert set(project_requests) == set(requirements_requests)
    for req in project_requests:
        assert not req.extras and req.url is None
        specifiers = list(req.specifier)
        upper = [spec.version for spec in specifiers if spec.operator == "<"]
        lower = [spec.version for spec in specifiers if spec.operator == ">="]
        assert upper == [expected[req.marker]]
        assert len(specifiers) == 2 and len(lower) == 1
        assert Version("2") <= Version(lower[0]) < Version(upper[0])


def test_requests_contract_agrees_between_parsed_manifests():
    _assert_requests_contract(_read("pyproject.toml"), _read("requirements.txt"))


@pytest.mark.parametrize("mutation", ["unconditional", "marker", "cap", "disagreement", "duplicate"])
def test_broken_requests_contract_is_a_failing_control(mutation):
    project = _read("pyproject.toml")
    requirements = _read("requirements.txt")
    if mutation in {"unconditional", "duplicate"}:
        extra = 'requests>=2.34.2,<3' if mutation == "unconditional" else str(
            Requirement(tomllib.loads(project)["project"]["dependencies"][0])
        )
        project = project.replace("dependencies = [", f"dependencies = [\n    '{extra}',", 1)
    elif mutation == "marker":
        project = project.replace("python_version < '3.10'", "python_version < '3.9'")
    elif mutation == "cap":
        project = project.replace("<2.33", "<3")
        requirements = requirements.replace("<2.33", "<3")
    else:
        requirements = requirements.replace("<2.33", "<2.34")
    with pytest.raises(AssertionError):
        _assert_requests_contract(project, requirements)


def test_compatible_requests_floor_updates_do_not_require_test_edits():
    project = _read("pyproject.toml")
    requirements = _read("requirements.txt")
    for value in tomllib.loads(project)["project"]["dependencies"]:
        req = Requirement(value)
        lower = next(spec.version for spec in req.specifier if spec.operator == ">=")
        raised = str(Version(lower)) + ".1"
        project = project.replace(">=" + lower, ">=" + raised)
        requirements = requirements.replace(">=" + lower, ">=" + raised)
    _assert_requests_contract(project, requirements)


def test_dependency_automation_respects_supported_python_and_held_action_contracts():
    config = yaml.safe_load(_read(".github/dependabot.yml"))
    updates = {entry["package-ecosystem"]: entry for entry in config["updates"]}

    action_ignores = {entry["dependency-name"] for entry in updates["github-actions"]["ignore"]}

    assert "hermes-labs-ai/lintlang" in action_ignores
    assert "intentional compatibility probe" in _read(".github/workflows/lintlang.yml")


def test_dependabot_merge_waits_for_required_checks_without_repository_auto_merge():
    workflow = _read(".github/workflows/dependabot-auto-merge.yml")

    wait = 'gh pr checks --required --watch --fail-fast "$PR_URL"'
    merge = 'python3 -I "$RUNNER_TEMP/little-canary-review-guard.py"'
    assert wait in workflow
    assert merge in workflow
    assert workflow.index(wait) < workflow.index(merge)
    assert '--head "$HEAD_SHA" --merge' in workflow
    assert "gh pr merge --auto" not in workflow
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in workflow


def test_scorecard_workflow_pins_actions_and_narrows_permissions():
    # Parse the executable document: comments and unrelated nodes must not be
    # able to satisfy the security contract asserted below.
    workflow = yaml.safe_load(_read(".github/workflows/scorecard.yml"))
    # PyYAML reads the bare ``on`` key as the YAML 1.1 boolean ``True``.
    triggers = workflow.get("on", workflow.get(True))
    analysis = workflow["jobs"]["analysis"]

    assert "branch_protection_rule" in triggers
    assert triggers["push"] == {"branches": ["main"]}
    assert triggers["schedule"], "scorecard workflow has no schedule trigger"
    for entry in triggers["schedule"]:
        assert re.fullmatch(r"(\S+ ){4}\S+", entry["cron"]), entry

    assert workflow["permissions"] == "read-all"
    assert analysis["permissions"] == {"security-events": "write", "id-token": "write"}

    pinned = _pinned_actions(analysis["steps"])
    assert {"ossf/scorecard-action", "github/codeql-action/upload-sarif"} <= pinned.keys()
