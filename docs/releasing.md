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
   distributions in a fresh directory outside the repository:
   ```sh
   release_head=$(git rev-parse HEAD)
   test -z "$(git status --porcelain)"
   python -m pip install --upgrade build twine
   release_dist=$(mktemp -d)
   python -m build --outdir "$release_dist"
   python -m twine check --strict "$release_dist"/*
   python -m pip hash "$release_dist"/*
   ```
   Install the wheel and source distribution into separate fresh environments
   outside the source checkout. Verify version and offline replay in each. Record
   `release_head` with the artifact hashes; if the source head changes, discard
   and rebuild the artifacts and repeat the affected checks.
5. Hand the frozen PR head, matching artifact record and proposed public copy to
   the separate controller. The controller rejects artifacts recorded for any
   other commit and follows
   [the existing readiness guard](maintainer-dependency-updates.md), including
   head-specific reviews, dispositions, quiet windows and fresh merged-main CI.
   The author must not merge or publish.

## Publish and synchronize

The existing [.github/workflows/publish.yml](../.github/workflows/publish.yml)
triggers only when a GitHub release is **published**. A tag push alone does not
publish to PyPI. After the reviewed PR is merged and fresh `main` CI passes, the
controller records that exact merged release commit, creates or verifies the
`v<package version>` tag, and proves the dereferenced tag targets that commit
before approving the curated title/body and publishing the release. A matching
tag name or package version alone is insufficient. Do not publish another version
merely to complete website synchronization.

After the publish run succeeds, verify public wheel and source downloads, hashes,
PyPI provenance, fresh no-cache installs, and README metadata. Offline replay
proves the packaged fixture path, not current live-model detection quality.
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
