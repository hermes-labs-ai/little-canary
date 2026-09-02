"""Release-version and repository-identity consistency checks."""

import json
import re
from pathlib import Path

from little_canary import __version__

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _match(relative_path: str, pattern: str) -> str:
    match = re.search(pattern, _read(relative_path), flags=re.MULTILINE)
    assert match is not None, f"{relative_path} does not match {pattern!r}"
    return match.group(1)


def test_release_version_surfaces_are_aligned():
    versions = {
        __version__,
        _match("pyproject.toml", r'^version = "([^"]+)"$'),
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
            "README.md",
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


def test_changelog_top_entry_is_a_dated_release_for_the_current_version():
    headings = re.findall(r"^## \[([^\]]+)\] - (.+)$", _read("CHANGELOG.md"), flags=re.MULTILINE)

    assert headings, "CHANGELOG.md contains no release headings"
    top_version, top_date = headings[0]
    assert top_version == __version__
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", top_date), top_date


def test_readme_release_guidance_stays_true_across_publication():
    readme = _read("README.md")

    # Durable guidance: point at live authorities and the local verification
    # command instead of freezing a snapshot of external registry state.
    assert "https://github.com/hermes-labs-ai/little-canary/releases" in readme
    assert "https://pypi.org/project/little-canary/" in readme
    assert "little-canary --version" in readme
    assert "pyproject.toml" in readme


def test_release_docs_do_not_assert_current_external_registry_state():
    for relative_path in ("README.md", "CHANGELOG.md"):
        text = _read(relative_path)

        assert "Unreleased" not in text, relative_path
        assert "currently publishes" not in text, relative_path
        assert "source candidate" not in text, relative_path
        assert "artifact exists" not in text, relative_path
        assert "Before publication" not in text, relative_path


def test_publish_workflow_keeps_build_privileges_away_from_publishing():
    workflow = _read(".github/workflows/publish.yml")
    build_workflow, publish_workflow = workflow.split("  publish:\n", maxsplit=1)
    build_job = build_workflow.split("  build:\n", maxsplit=1)[1]

    assert "  release:\n    types: [published]" in workflow
    assert "  build:\n" in workflow
    assert "    permissions:\n      contents: read\n" in build_job
    assert "id-token: write" not in build_job
    assert 'test "${GITHUB_REF_NAME}" = "v${package_version}"' in build_job
    assert "python -m build" in build_job
    assert "python -m twine check dist/*" in build_job
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in build_job
    assert "    needs: build\n" in publish_workflow
    assert "      contents: read\n      id-token: write" in publish_workflow
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in publish_workflow
    assert "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in publish_workflow


def test_dependabot_merge_waits_for_required_checks_without_repository_auto_merge():
    workflow = _read(".github/workflows/dependabot-auto-merge.yml")

    wait = 'gh pr checks --required --watch --fail-fast "$PR_URL"'
    merge = 'gh pr merge --squash --match-head-commit "$HEAD_SHA" "$PR_URL"'
    assert wait in workflow
    assert merge in workflow
    assert workflow.index(wait) < workflow.index(merge)
    assert "gh pr merge --auto" not in workflow
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha }}" in workflow
