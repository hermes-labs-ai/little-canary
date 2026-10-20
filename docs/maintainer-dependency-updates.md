# Maintainer dependency updates

Dependabot checks GitHub Actions weekly and groups routine updates in
`.github/dependabot.yml`. It explicitly ignores `hermes-labs-ai/lintlang`.
The held compatibility probe is v0.7.1 at
`6aace2a175483757c64d7aa2105346d1cc34b857`; a scheduled Dependabot run will
not propose advancing it. PR #69 is historical evidence of discovery before
this exclusion, not evidence of the current update policy.

## Changing the held LintLang probe

Use a dedicated semantic-review PR. Verify the proposed release SHA against
upstream, compare its diagnostics and failure behavior on our agent instructions,
and review the compatibility impact. Update the workflow's immutable SHA and
version comment, `PINNED_LINTLANG_REF` in
`tests/test_lintlang_dependency_contract.py`, and this guide together.
`UNAPPROVED_LINTLANG_REF` records a rejected pair for the negative control; it
is not an automatically advancing latest-release pointer. A newer release alone
does not authorize changing the held pair. Tests require exactly one approved
LintLang invocation across the workflows and local action manifests, and reject
additional invocations or tags.

## Requests compatibility

The project dependencies and `requirements.txt` must agree on exactly two
Requests requirements: Python below 3.10 has a `<2.33` cap; Python 3.10 and above
has a `<3` cap. Compatible lower-bound updates may advance both manifests without
editing tests. Verify actual Python 3.9 resolution when changing its lower bound;
the structural contract does not prove that an upstream version exists or supports
that interpreter.

## Merge and release readiness

A successful review check is not approval or evidence of zero findings. The
authoring session may push/open/update a PR but must hand the final diff and
head SHA to a separate reviewer and merge controller, who alone decides and
executes the merge. For every PR, wait for head-specific CI and actual Sourcery
and Copilot review submissions,
read their full bodies and all threads, address valid findings, and resolve only
threads whose fixes have been verified. Pending reviewer requests, pending reviews,
changes requested, and unresolved threads hold the merge. Outdated threads still
require disposition. Recheck immediately before merging against the exact head:

```bash
gh pr checks --required --watch --fail-fast <PR_URL>
python3 scripts/check_pr_readiness.py --repo hermes-labs-ai/little-canary \
  --pr <PR_NUMBER> --head <REVIEWED_HEAD_SHA>
gh pr merge --squash --match-head-commit <REVIEWED_HEAD_SHA> <PR_URL>
```

The guard observes a stable head and unchanged review activity for 120 seconds,
including after the latest push first seen by the controller. Any review or thread
activity restarts the quiet window. Both bots must submit on that exact head; the
15-minute timeout fails closed with no timeout waiver.

The same guard is required before release readiness is handed back, using the
merged PR's reviewed head SHA, followed by fresh main CI verification. The script
queries review submissions, reviewer requests, and every review-thread page;
it does not infer review completion from a bot check. The Dependabot merge workflow
uses this guard too. A missing review keeps the lane held; do not bypass it to
unblock automation. No finite snapshot prevents a reviewer from submitting a new
review later: both expected bot submissions and a final live query are required.
PR #155's 2026-10-20 timing is a regression fixture: Sourcery's findings preceded
the merge by three seconds, and Copilot's submission followed the merge.

This is an enforced instruction for Hermes author/controller sessions and an
executable guard in Dependabot's merge job. It is not repository-wide merge
protection: the current branch policy requires no approvals and permits owner/admin
bypass. Do not claim those GitHub bypass paths have been removed. Required checks
are read from the existing branch protection and matched to the expected commit's
status rollup using GitHub's required-check identity, including its app binding.
