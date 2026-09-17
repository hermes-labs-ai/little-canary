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

The workflow currently pins v0.5.3 at
`f89c3b0b8986fad162859dca052a8d5fe227eede`. The known newer release is v0.6.0
at `58e66871531eb585869336189d07b4334e963a5f`. The next scheduled Dependabot
run should therefore surface the same kind of versioned update for review.

To inspect the provider's live result and verify the exact action reference:

```bash
gh pr list -R hermes-labs-ai/little-canary --author app/dependabot \
  --search '"hermes-labs-ai/lintlang"' --state open
gh pr diff <DEPENDABOT_PR> -R hermes-labs-ai/little-canary
gh pr checks <DEPENDABOT_PR> -R hermes-labs-ai/little-canary
```

The expected update is a single workflow-line change to
`hermes-labs-ai/lintlang@58e66871531eb585869336189d07b4334e963a5f # v0.6.0`.
Do not replace the SHA with `@main` or a release tag; the test suite includes a
failing tag-ref control for that regression.
