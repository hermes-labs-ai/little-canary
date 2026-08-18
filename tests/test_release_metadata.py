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


PYPI_PUBLISHED_VERSION = "0.3.3"


def test_readme_distinguishes_source_candidate_from_published_release():
    readme = _read("README.md")

    assert f"PyPI currently publishes `{PYPI_PUBLISHED_VERSION}`" in readme
    if __version__ != PYPI_PUBLISHED_VERSION:
        assert f"unpublished `{__version__}` source candidate" in readme
        assert f"PyPI currently publishes `{__version__}`" not in readme
    assert "Before publication" not in readme
    assert "PyPI remained on `0.3.0`" not in readme


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
