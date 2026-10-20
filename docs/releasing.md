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
   `little_canary_version`. Update current install pins in `llms.txt` and the
   OpenClaw README. Curate the dated changelog and proposed release title/body
   from the actual diff. Preserve historical evidence, unrelated tool pins and
   host certification fields. Do not rewrite the root README for a version bump.
3. Dry-run the native validation without changing release state:
   ```sh
   python -m pytest -q tests/test_release_metadata.py
   little-canary --version
   little-canary demo --replay --json
   ```
   Then prepare distributions in a fresh directory outside the repository:
   ```sh
   release_dist=$(mktemp -d)
   python -m build --outdir "$release_dist"
   python -m twine check --strict "$release_dist"/*
   ```
   Install the wheel and source distribution into separate fresh environments
   outside the source checkout. Verify version and offline replay in each.
   Run the repository's required native checks and Gate fast/full/review.
4. Freeze the authoring head in a PR. Hand it, artifacts and proposed public copy
   to the separate controller. The controller follows
   [the existing readiness guard](maintainer-dependency-updates.md), including
   head-specific reviews, dispositions, quiet windows and fresh merged-main CI.
   The author must not merge or publish.

## Publish and synchronize

The existing [.github/workflows/publish.yml](../.github/workflows/publish.yml)
triggers only when a GitHub release is **published**. A tag push alone does not
publish to PyPI. The controller checks the `v<package version>` tag, approves
curated title/body, and owns release publication. Do not publish another version
merely to complete website synchronization.

After the publish run succeeds, verify public wheel and source downloads, hashes,
PyPI provenance, fresh no-cache installs, and README metadata. Offline replay
proves the packaged fixture path, not current live-model detection quality.

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
