# Maintainer dependency updates

Dependabot checks GitHub Actions weekly and groups routine updates in
`.github/dependabot.yml`. It explicitly ignores `hermes-labs-ai/lintlang`.
The held compatibility probe is v0.7.1 at
`6aace2a175483757c64d7aa2105346d1cc34b857`; scheduled runs do not propose advancing
it. PR #69 documents discovery before this exclusion, not the current policy.

## Changing the held LintLang probe

Use a dedicated semantic-review PR. Verify the proposed release SHA against
upstream, compare its diagnostics and failure behavior on our agent instructions,
and review the compatibility impact. Update the workflow's immutable SHA and
version comment, `PINNED_LINTLANG_REF` in
`tests/test_lintlang_dependency_contract.py`, and this guide together.
`UNAPPROVED_LINTLANG_REF` records a rejected pair for the negative control; it
is not an automatically advancing latest-release pointer. A newer release alone
does not authorize changing the held pair. Tests require exactly one approved
LintLang invocation across workflows and local action manifests, including
composites under build, dist, node_modules or .venv directories.

## Requests compatibility

The project dependencies and `requirements.txt` must agree on exactly two
Requests requirements: Python below 3.10 has a `<2.33` cap; Python 3.10 and above
has a `<3` cap. Compatible lower-bound updates may advance both manifests without
editing tests. Verify actual Python 3.9 resolution when changing its lower bound;
the structural contract does not prove an upstream version exists or supports it.

## Merge and release ownership

The authoring session may push/open/update a PR, but a separate reviewer and
merge controller alone decides and executes its merge. The controller reads full
review bodies and all threads, addresses valid findings, and resolves threads
only with verified evidence. A successful bot check is not approval or evidence
of zero findings. Both Copilot and Sourcery must submit on the exact head.
Pending requests, API-visible pending reviews, changes requested, and unresolved
threads (including outdated ones) hold readiness. Other users' private draft
reviews are invisible to the controller token; the guard cannot establish their
absence. Requested reviewers must submit before handback.

Every nonempty review body also holds readiness until the controller explicitly
disposes it. The guard does not guess whether free-form English contains a
finding, so even a clean summary needs disposition. After reading the body and
verifying each finding, the independent controller posts a native PR comment:

```text
<!-- little-canary-review-disposition/v1 -->
{"head":"<REVIEWED_HEAD_SHA>","reviews":[{"id":"<GRAPHQL_REVIEW_ID>","digest":"<REVIEW_DIGEST>","disposition":"addressed","evidence":"<fix/tests, or reason no action is needed>"}]}
```

Use `addressed` for verified fixes or `no-action` with a concrete reason. The
read-only guard reports the review ID and digest for undisposed bodies. The
digest covers the complete review object read from GitHub; a review edit or a
new PR head invalidates the disposition. One comment may dispose multiple
reviews. Only GitHub-reported OWNER, MEMBER or COLLABORATOR comments qualify.
The authoring session must not post controller dispositions. GitHub account
membership cannot prove Codex session separation; that separation is enforced
by the Hermes session instructions, and the controller remains responsible for
the evidence it records. A disposition never overrides an unresolved thread,
change request, missing expected review, or failed check.

The independent controller invokes the trusted guard with `--merge`, which
observes a 120-second quiet window, confirms complete review/check state again,
then performs a fresh final recheck immediately before its head-matched merge:

```bash
python3 -I scripts/check_pr_readiness.py --repo hermes-labs-ai/little-canary \
  --pr <PR_NUMBER> --head <REVIEWED_HEAD_SHA> --merge
```

Omit `--merge` for read-only readiness and release handback, then verify fresh
main CI. Every API call is bounded by 30 seconds or the remaining overall
15-minute deadline, whichever is shorter. A fetch returning after the deadline
cannot grant readiness. Any observed activity restarts the quiet window or holds
the current attempt. Missing reviews, API errors, and incomplete pagination fail
closed. GitHub does not support an atomic review-state condition on the merge
API; activity after the final query and before server-side merge remains a
residual race. This procedure narrows that gap and does not claim to remove it.

Required checks come from the classic branch policy and the exact commit's
status rollup, using GitHub's required-check app binding. Only the latest attempt
of each required check identity is evaluated. All configured contexts must be
present and successful; `SKIPPED` and `NEUTRAL` hold coverage readiness. A missing
classic policy holds explicitly rather than inferring completeness from whatever
checks happen to be present. A ruleset migration must update this query first.

## Automation retries and limits

The Dependabot job is a separate controller. It reads check runs and statuses,
extracts its guard from the trusted event base commit, and executes that extracted
file in Python isolated mode. Every checkout before the guard must use that
base. Supported review submission/edit/dismissal and inline-comment events
restart the job for Dependabot-authored PRs, regardless of the review event actor.
GitHub Actions has no review-thread-resolution trigger. The running guard observes
resolutions while polling; after a timeout, thread resolution, disposition comment,
or transient API failure, rerun the existing run:

```bash
gh run rerun <RUN_ID> --repo hermes-labs-ai/little-canary
```

The event's head must still match. Rebase PRs whose event base predates this guard
onto corrected main, then use their new run. Missing bot submissions keep the
lane held; obtain those reviews and rerun. There is no timeout waiver.

This is an executable guard in Dependabot and an instruction for Hermes sessions.
The current branch policy requires no approvals and permits owner/admin bypass;
this is not repository-wide merge protection. PR #155's timing remains a regression
fixture: Sourcery's findings preceded merge by three seconds and Copilot followed.
