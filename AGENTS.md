# AGENTS.md

<!-- Instruction contract v1.0 — 2026-09-09 -->

Priority order: preserve security and coverage semantics; preserve public API behavior;
then minimize the diff. Treat each user request as an independent task and carry prior
task state forward only when the user explicitly asks.

Little Canary is a prompt-injection detection library that uses a sacrificial canary model as an inbound risk sensor.

## Use it for

- screening untrusted text before it reaches a main model or agent
- combining structural pattern checks with behavioral compromise checks
- returning `block`, `flag`, `pass`, or `degraded` state plus advisory text

## Do not use it for

- formal security guarantees
- audited benchmark comparisons
- replacing runtime containment or outbound tool controls

## Key paths

- `little_canary/` — package source
- `tests/` — pytest suite
- `benchmarks/` — false-positive/red-team runners, not part of the default CLI flow
- `.hermes/` — declared quality-gate config run by CI's Hermes quality rail
- `docs/host-capability-matrix.json` — per-host interception claims, enforced by
  `tests/test_host_capability_matrix.py`; `docs/host-capability-matrix.md` is its prose form
- `docs/host-evidence/` — verbatim host declarations backing those claims; re-extract, never edit

## Minimal commands

```bash
pip install -e ".[dev]"
little-canary --version
little-canary demo  # offline replay; runs with zero extra dependencies
little-canary demo --live --backend ollama --model qwen2.5:1.5b --endpoint http://127.0.0.1:11434
little-canary serve --help
little-canary ingest --help
pytest -q
ruff check little_canary tests
mypy little_canary
python -m build
```

## Output shape

- Python API separates routing (`safe`) from coverage (`degraded`, `canary_status`, `analysis_method`, `analysis_status`)
- failed/unavailable coverage keeps risk unset and never means an exercised PASS
- CLI exposes explicit replay/live demo paths and the local HTTP server
- benchmark scripts live under `benchmarks/` and are not part of the default CLI flow

## Success means

- when an admitted fixture is packaged, replay reproduces analyzer behavior for those exact bytes without a network call
- a build without that fixture must report `REPLAY UNAVAILABLE`; this is a hold, not a safe result
- live evidence names its backend, model digest, configuration, and observed result
- structural and behavioral layers agree with the documented modes
- the Ollama path and OpenAI-compatible protocol adapter pass their declared
  offline tests; live support remains bound to endpoint-specific evidence
- a host integration claims only what that host version can do: inbound prompt
  screening and outbound tool-execution blocking stay separate claims, and a
  host that cannot refuse a prompt is documented as unable to

## Common failure cases

- the canary backend is unavailable and fail-open routing passes through with a visible degraded state
- users expect this tool to replace broader agent runtime controls
- benchmark claims are quoted without the methodology caveats in the README

## Maintainer notes

- preserve fail-open behavior unless there is an explicit versioned policy change
- never treat replay, mock, or static evidence as a current live-model result
- never raise a host's `runtime_certified` flag on manifest parsing alone; record
  what was observed, on which host version, in `docs/host-capability-matrix.json`
- keep benchmark caveats aligned with README claims
- keep tests offline and mock network calls

## Merge and release ownership

The authoring session may push, open, and update a PR, but must not decide or
execute its merge. Hand the final diff and exact head SHA to a separate reviewer
and merge controller. That controller reads full review bodies and threads, then
runs `python3 -I scripts/check_pr_readiness.py --repo hermes-labs-ai/little-canary
--pr <NUMBER> --head <SHA> --merge` only after accepting that exact head. The guard
requires passing required checks, both head-specific Copilot and Sourcery review
submissions, no pending requests/API-visible pending reviews or changes requested,
zero unresolved threads (including outdated ones), explicit controller disposition
of every nonempty review body, and 120 seconds of observed stable head and review
activity. GitHub hides other users' private draft reviews; this guard cannot prove
they do not exist. Ask requested reviewers to submit before handing back readiness.
The controller posts dispositions in native PR comments bound to the exact head,
review ID and digest, with evidence. The authoring session must not post controller
dispositions. Read the format and trust limits in the maintainer guide. The guard
rechecks complete review activity immediately before its head-matched merge; the
GitHub API does not offer an atomic condition on review state for that merge.
Its deadline bounds CLI requests and fails closed; a successful bot check is
insufficient. Repeat the read-only guard (omit `--merge`) before a release handback,
and verify fresh main CI. See
`docs/maintainer-dependency-updates.md` for the procedure. Do not release from an
authoring lane or bypass a hold to sustain forward momentum.

## Definition of done

- `pytest -q` and `ruff check little_canary tests` pass; `mypy little_canary` is diagnostic
- new behavior has an offline, mocked-network test
- fail-open behavior and coverage-state semantics are unchanged unless explicitly intended
- README and this file stay consistent with observed CLI/API behavior
- a change to any host adapter updates `docs/host-capability-matrix.json` in the same commit

## Optional Hermeneutic Gate

For a consequential semantic review of an assistant-generated English draft,
you may run the standalone deterministic second-opinion check from the
separate [Hermeneutic Gate](https://github.com/hermes-labs-ai/hermeneutic#epistemic-gate)
CLI. It is not part of Little Canary's dev extras; install it separately:

```bash
python -m pip install hermeneutic
hermeneutic gate --draft review-summary.md
```

It flags surface shapes such as completion overclaiming, unsupported numeric
claims, relayed authority, and unhedged certainty. It runs offline, does not
invoke Little Canary or a model backend, and does not create a release or
perimeter gate. This optional Hermeneutic Gate is separate from the
repository's configured Hermes Gate quality rail; callers choose whether
and how to enforce its exit code. Per the
[quick start](https://github.com/hermes-labs-ai/hermeneutic#quick-start),
low-severity `RISK` is advisory (exit 0); medium/high `RISK` exits 1. If it
flags a claim, add direct evidence, hedge the claim, or remove the
unverifiable wording.
