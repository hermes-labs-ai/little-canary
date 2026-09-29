# Maintainer dependency updates

Little Canary opts into GitHub Dependabot's `github-actions` ecosystem in
`.github/dependabot.yml`. It checks weekly and groups action updates into one
reviewable pull request. The LintLang workflow keeps a full commit SHA plus a
human-readable release comment so the executed action is immutable while the
dependency remains discoverable to Dependabot.

## Current proof and next update

The repository has already accepted this exact provider path: Dependabot's
[merged PR #69](https://github.com/hermes-labs-ai/little-canary/pull/69) updated
`hermes-labs-ai/lintlang` from v0.5.0 to v0.5.3 by changing the `uses:` SHA in
`.github/workflows/lintlang.yml`.

The workflow intentionally pins one release behind: v0.7.1 at
`6aace2a175483757c64d7aa2105346d1cc34b857`. The known newer release is v0.8.0
at `c0cab00048220286858f227aaf4b13cc043f718b`. The next scheduled Dependabot
run should therefore surface the same kind of versioned update for review.

To inspect the provider's live result and verify the exact action reference:

```bash
gh pr list -R hermes-labs-ai/little-canary --author app/dependabot \
  --search '"hermes-labs-ai/lintlang"' --state open
gh pr diff <DEPENDABOT_PR> -R hermes-labs-ai/little-canary
gh pr checks <DEPENDABOT_PR> -R hermes-labs-ai/little-canary
```

The expected proposal changes the workflow reference to
`hermes-labs-ai/lintlang@c0cab00048220286858f227aaf4b13cc043f718b # v0.8.0`.
That proposal demonstrates Dependabot discovery; do not accept v0.8.0 while it
is the latest release if retaining the intentionally one-release-behind policy.
Once a newer release is available, verify both release SHAs and approve the
workflow update together with `PINNED_LINTLANG_REF` and `CURRENT_LINTLANG_REF`
in `tests/test_lintlang_dependency_contract.py`: the pinned pair must identify
the approved release immediately before the current pair. Update this guide
to match those reviewed pairs.
Do not replace the SHA with `@main` or a release tag; the test suite includes a
failing tag-ref control for that regression.
