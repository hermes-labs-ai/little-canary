# Little Canary release entrypoint

Start here from a fresh maintainer session. Follow `AGENTS.md` for author/controller
ownership and `.hermes/gate.toml` for required checks. Release preparation changes
source; publication is a separate controller action.

## Prepare and verify (no publication)

1. Fetch current `main`, inspect the diff and open PRs, and use a clean branch.
2. Treat `pyproject.toml` as the package version source. Update the matching
   versions in `little_canary/__init__.py`, the vendored
   `integrations/hermes-agent/little_canary/__init__.py`,
   `integrations/hermes-agent/plugin.yaml`, `CITATION.cff`, `.zenodo.json`,
   `codemeta.json`, `gemini-extension.json`,
   `plugins/claude-code/.claude-plugin/plugin.json`, the OpenClaw/OpenCode/Pi
   `package.json` files, and `docs/host-capability-matrix.json`'s
   `little_canary_version`. The JavaScript manifest versions are source and
   compatibility metadata checked by this repository; this Python release does
   not publish the intentionally unpublished OpenCode/Pi npm packages or update
   a ClawHub package. Treat any registry publication as a separate release.
   Update current install pins in `llms.txt` and both the service-version text
   and install pin in the OpenClaw README. Keep the new changelog heading
   `Unreleased` and omit `codemeta.json`'s future `downloadUrl` while preparing;
   curate the proposed release title/body from the actual diff. Preserve
   historical evidence, unrelated tool pins and host certification fields. Do
   not rewrite the root README for a version bump.
3. Dry-run the native validation without changing release state:
   ```sh
   python -m pytest -q tests/test_release_metadata.py
   little-canary --version
   little-canary demo --replay --json
   ```
   Run the remaining required native checks, commit the candidate, and run Gate
   fast/full/review on that exact head. Resolve findings in a new commit and
   repeat affected checks; freeze the head only when the committed tree is clean.
4. From that exact clean head, install the packaging tools and prepare
   distributions in a fresh directory outside the repository. Run this as a
   standalone script, not in the maintainer's interactive shell:
   ```sh
   #!/bin/sh
   set -eu
   release_head=$(git rev-parse HEAD)
   test -z "$(git status --porcelain)"
   python -m pip install --upgrade build twine
   release_dist=$(mktemp -d)
   python -m build --outdir "$release_dist"
   python -m twine check --strict "$release_dist"/*
   python -m pip hash "$release_dist"/*
   test "$(git rev-parse HEAD)" = "$release_head"
   test -z "$(git status --porcelain)"
   ```
   Install the wheel and source distribution into separate fresh environments
   outside the source checkout. Verify version and offline replay in each. Record
   `release_head` with the artifact hashes as pre-merge evidence; if the source
   head changes, discard and rebuild them and repeat the affected checks.
5. Hand the frozen PR head, its artifact record and proposed public copy to the
   separate controller. The controller verifies the recorded `release_head`
   equals the exact PR head and rejects a stale record, then follows
   [the existing readiness guard](maintainer-dependency-updates.md), including
   head-specific reviews, dispositions, quiet windows and fresh merged-main CI.
   The author must not merge or publish.

## Publish and synchronize

The existing [.github/workflows/publish.yml](../.github/workflows/publish.yml)
triggers only when a GitHub release is **published**. A tag push alone does not
publish to PyPI. After the reviewed PR is merged and fresh `main` CI passes, the
controller checks out that exact merged release commit and repeats the build,
Twine, separate wheel/sdist installation, version, replay and hash checks above.
Pre-merge artifacts do not substitute for this rebuild because squash merge
changes the commit identity. The controller then creates or verifies the
`v<package version>` tag and proves the dereferenced tag targets the rebuilt
merged commit before approving the curated title/body and publishing the release.
A matching tag name or package version alone is insufficient. Do not publish
another version merely to complete website synchronization.

The local hashes are pre-publication build evidence, not a claim that separately
built archives are byte-for-byte reproducible. After the publish run succeeds,
download the public wheel, source archive and each file's Integrity API provenance
to local files, then match each archive's SHA-256 to PyPI's published digest. Use a
reviewed, recorded exact verifier version (currently `pypi-attestations==0.0.30`),
not a floating install. Query the candidate publish run through `gh api
repos/hermes-labs-ai/little-canary/actions/runs/<run-id>` and require `status` to be
`completed`, `conclusion` to be `success`, `event` to be `release`, `path` to be
`.github/workflows/publish.yml`, `head_branch` to equal the release tag, and
`head_sha` to equal `git rev-parse '<tag>^{commit}'`. Record its `id` and
`run_attempt`; an earlier attempt is not interchangeable.

For each local archive and provenance file, run the repository check and extract
exactly one matching publish attestation:

```sh
pypi-attestations verify pypi \
  --repository https://github.com/hermes-labs-ai/little-canary \
  --provenance-file "$provenance" "$archive"
jq -e '
  [.attestation_bundles[]
   | select(.publisher.kind == "GitHub"
            and .publisher.repository == "hermes-labs-ai/little-canary"
            and .publisher.workflow == "publish.yml")
   | .attestations[]] as $matches
  | if ($matches | length) == 1 then $matches[0]
    else error("expected exactly one matching publish attestation") end
' "$provenance" > "$archive.publish.attestation"
```

Then use the verifier's public Python API to cryptographically bind those same
archive bytes to the tag commit, release trigger and recorded run attempt:

```python
import os
from pathlib import Path

from pypi_attestations import Attestation, Distribution
from sigstore.verify import policy

tag = os.environ["TAG"]
release_commit = os.environ["RELEASE_COMMIT"]
run_id = os.environ["RUN_ID"]
run_attempt = os.environ["RUN_ATTEMPT"]
archive = os.environ["ARCHIVE"]
repo = "https://github.com/hermes-labs-ai/little-canary"
ref = f"refs/tags/{tag}"
workflow = f"{repo}/.github/workflows/publish.yml@{ref}"
checks = policy.AllOf(
    [
        policy.Identity(
            identity=workflow,
            issuer="https://token.actions.githubusercontent.com",
        ),
        policy.OIDCSourceRepositoryURI(repo),
        policy.OIDCSourceRepositoryDigest(release_commit),
        policy.OIDCSourceRepositoryRef(ref),
        policy.OIDCBuildConfigURI(workflow),
        policy.OIDCBuildTrigger("release"),
        policy.OIDCRunInvocationURI(
            f"{repo}/actions/runs/{run_id}/attempts/{run_attempt}"
        ),
    ]
)
attestation = Attestation.model_validate_json(
    Path(f"{archive}.publish.attestation").read_bytes()
)
attestation.verify(identity=checks, dist=Distribution.from_file(Path(archive)))
```

Export `TAG`, `RELEASE_COMMIT`, `RUN_ID`, `RUN_ATTEMPT` and `ARCHIVE` from the
verified values above before running the snippet; any missing extension or mismatch
is a hold. Perform this for both archives, then do fresh no-cache installs and
check README metadata.
Offline replay proves the packaged fixture path, not current live-model detection
quality.
In a follow-up metadata PR, date the changelog entry and add
`codemeta.json`'s now-live versioned PyPI `downloadUrl`; do not move the immutable
release tag or publish again for that metadata-only change.

Only after that public-install gate passes, synchronize current references.
The existing company-site entrypoint in `roli-lpci/hermes-labs-v2` is:

```sh
node scripts/release-truth-refresh.mjs --prepare little-canary          # dry run
node scripts/release-truth-refresh.mjs --prepare little-canary --write # prepare
npm run generate:llms
npm run generate:catalog
node scripts/build-fact-sheet.mjs
```

Repeat the prepare command and generators: the second pass must change no bytes.
Use that site's publishing instructions and normal PR/deployment pipeline.
`docs/cross-site-product-truth-2026-10-08.md` in the company-site repo maps
`littlecanary.ai` to `roli-lpci/little-canary-website`; use its approved active
checkout and native sync/check commands. Missing workspace authority is a hold,
not permission to substitute a checkout. Preserve older host evidence, archived
releases and independently pinned integrations. Close with public release/package
links, exact PRs/commits, deployment readbacks and any blocked surface.
