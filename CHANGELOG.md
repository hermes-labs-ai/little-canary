# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Benchmark and latency figures in entries before `0.3.3` are historical release notes, not current support or performance claims.

## [0.5.0] - Unreleased

### Added

- `little-canary screen` and `little_canary.batch.screen_batch`: batch pre-screening with independent per-item verdicts, provenance (index/id/source/SHA-256), per-item errors reported as `degraded` (never `pass`), no echo of item text, and all-or-nothing admission with item-count, per-item and aggregate byte limits. Safety semantics of `SecurityPipeline.check` are unchanged.
- Experimental Ingest surface: the `little-canary ingest` CLI and the Python module `little_canary.ingest` (`ingest_records`, `IngestPolicy`, `IngestRecord`, `IngestResult`, `publish`, `write_manifest`, `write_export`, `verify_export`, `required_canary_context`, `loads_strict`). Each JSONL record (`text`, optional `id`, `source`, `metadata`) is checked through `SecurityPipeline.check` and admitted or held under the `strict/v1` policy.
- Three separate per-record states: detection (`none`/`flag`/`block`), coverage (`complete`/`partial`/`none`) and admission (`admitted`/`held`). A record is admitted only with detection `none`, coverage `complete` and every segment `pass`.
- Hold reasons, all listed when they apply: `malformed`, `over_budget`, `blocked`, `flagged`, `degraded`, `unexercised`, `error`, `incomplete`. Record-level validation failures (including unknown top-level keys and non-string metadata values) hold the record instead of coercing it. From Python, a `str`-subclass metadata key, or a record mapping whose `metadata` yields the same key twice when ingest reads it, makes the record `malformed` instead of being merged.
- Admission is decided from the verdict snapshot recorded in the manifest, taken with `PipelineVerdict.to_dict` as defined by the class (a `to_dict` set on the verdict instance is ignored) and classified after the manifest's JSON serialization, so each field is judged as the plain value recorded; a verdict that cannot be serialized is an `error` hold. A non-finite or out-of-range risk score, a mistyped or self-contradictory verdict, a verdict for other text, or a `PipelineVerdict` subclass is an `error` hold; a measured non-zero risk score is `flag`, never `pass`.
- Deterministic segmentation with a per-record budget (`--segment-chars`, `--segment-overlap`, `--max-segments`, `--max-item-bytes`) and character-level coverage accounting. A record over budget is held with zero checks; a record is never partly scanned and reported as screened. A single JSONL line longer than the reader's cap (`read_records`, derived from `--max-item-bytes` and the metadata limits) refuses the whole run before any check, independent of the per-record `over_budget` hold.
- Canary context verification before any check: the Ollama canary's `num_ctx` must be at least `4 × segment_chars + 4 × len(system prompt) + max_tokens + 64` (`required_canary_context`; the CLI sets it to exactly this value), and the model's trained context length reported by Ollama's `/api/show` must be at least as large, because Ollama caps `num_ctx` at the trained length and truncates the prompt. If either fails, or the trained length cannot be read (backend unreachable, model unknown), the run is refused (CLI exit `3`, nothing written); for `ingest` an unreachable backend at the start is a run-level refusal, not a per-record `degraded` hold as in `screen`. Both values are recorded as `pipeline.canary_num_ctx` and `pipeline.canary_context_length`. Python callers pass a `SecurityPipeline` constructed with `SecurityPipeline(canary_num_ctx=required_canary_context(policy, pipeline))` or larger; a smaller or unset `num_ctx` makes `ingest_records` raise `ValueError` before any check. A pipeline that is not a `SecurityPipeline` (a wrapper, a stand-in, or a subclass or instance overriding `check`) also raises `ValueError` before any check, unless the caller passes `unverified_pipeline=True` (tests, stand-ins); the manifest then records `pipeline.canary_context_verified: false` and `verify_export` refuses the pair. `canary_context_verified` is `true` only when a `SecurityPipeline`'s Ollama canary passed the verification.
- Ingest does not support `provider="openai"` or `judge_model` in 0.5.0: with the canary enabled, either raises `ValueError` with the reason before any check. With `enable_canary=False` a run completes, but no record can be admitted (segments are held `unexercised`, or `blocked` by the structural filter).
- `id`, `source` and `metadata` are screened as material, before the text, because the export emits them downstream.
- Input from a file or stdin is decoded as strict UTF-8 regardless of locale; an object with a duplicate key is malformed JSON and refuses the whole run.
- Manifest `little-canary-ingest-manifest/v1`, written when a run completes. It carries hashes, lengths, offsets, states, hold reasons, detector-generated signals and verdict summaries with the raw input fields removed, pipeline configuration (mode, provider, model, `canary_num_ctx`, `canary_context_length`, `canary_context_verified`; never URLs or keys), timestamps, `run.input_sha256` (the exact input bytes, set by the CLI) and `run.export_requested`. `id`/`source` labels and metadata key names appear in plaintext only for admitted records; held records carry `id_sha256`/`source_sha256`/`metadata_key_count` instead. Record text and metadata values never appear.
- Opt-in export `little-canary-ingest-export/v1` (`--export`): only admitted records, in record order, exact snapshot text, per-record `sha256`/`material_sha256`, and the `manifest_sha256` it is bound to.
- Publication (`publish`, used by the CLI): nothing is written until the run completes; both documents are written to temp files, the export is published first and the manifest last. If publication raises (including on `KeyboardInterrupt`), every temp file it wrote (an empty temp file created in the instant before it is registered can remain) and every file published in that call is removed, so a failed or interrupted run leaves no new manifest. Existing paths are refused unless `--overwrite`: the previous manifest and export are removed after the limits and `LITTLE_CANARY_TIMEOUT` are validated (a value that fails leaves them untouched, exit `3`) and before the run starts, so any later failure leaves no pair rather than a stale one.
- Exit status: `0` all admitted; `1` held for detection only; `2` run completed and files written, but some record held for an operational or coverage reason; `3` nothing written (invalid input or configuration, empty input, unusable or existing output paths, unwritable output directory, canary context that fails verification, malformed JSON including duplicate keys, a line over the reader's cap or another run-level limit, write failure). Exit `3`, not `2`, means nothing was written, so that `2` can report a completed run with operational holds; this, and splitting the entry point into `ingest_records` (screen) and `publish` (write) instead of a single `ingest()`, are deliberate departures from the pre-release design draft.
- `verify_export` checks that an export and its manifest are consistent (schemas, exact field set, hash binding including optional raw manifest bytes, `run.export_requested`, `pipeline.canary_context_verified: true`, admitted set and order, per-segment evidence, segments equal to the plan rebuilt from the manifest policy over the exported text and metadata material with matching spans and `sha256`, `chars_total`, counts, digests); it does not check authenticity, since anyone who can write both files can forge a matching pair.
- Consumer example `examples/ingest_consumer.py`, which refuses an export that fails `verify_export`, requires `--expect-manifest-sha256` (the manifest sha256 printed by the ingest run) and refuses without it unless `--allow-unpinned` is given, which consumes a consistency-checked pair with a warning.
- Evaluation tooling in `benchmarks/ingest_eval/` (corpus and `run_eval.py`) that scores detector misses and false holds separately from operational/coverage holds.

**Experimental.** The Ingest command, schemas and `strict/v1` policy are experimental.

**Not claimed.** Admitted means the record completed every configured check and satisfied the policy; it is not a statement that the content is harmless. This release makes no detection-rate or latency claim for Ingest. PDF, DOCX, OCR and mailbox input are out of scope. Runtime fail-open routing is unchanged, and a fail-open (`degraded`) verdict never becomes ingest admission.

### Unchanged

- Runtime `SecurityPipeline.check`, `screen`, `serve` and `demo` semantics are untouched by Ingest.
- Runtime: `CanaryProbe(num_ctx=...)` and `SecurityPipeline(canary_num_ctx=...)` are new optional parameters. The default `None` sends no `num_ctx`, so Runtime behavior is unchanged.
- Runtime: `CanaryProbe.context_length()` (a read-only `/api/show` query) and `CanaryProbe.last_context_length` are new; only `ingest` calls `context_length()`, so `check`, `screen`, `serve` and `demo` make no additional request.

### Fixed

- Pi install: the documented `pi install npm:@hermes-labs/little-canary-pi@0.4.0` returned 404 because the npm package was never published. A private root `package.json` now exposes only `plugins/pi/index.js`, so `pi install git:github.com/hermes-labs-ai/little-canary` works natively.

## [0.4.0] - 2026-09-29

Minor release. Bare `little-canary demo` now works out of the box with a
packaged offline replay fixture (no Ollama, no model pull), and the canary
timeout is configurable with a default that CPU-only hardware can actually
meet. No changes to the default canary, detector rules, or fail-open routing.

### Added

- Packaged offline replay fixture (`little_canary/data/demo_replay.json`): bare
  `little-canary demo` now runs the offline demo (clean → PASS, injected →
  BLOCK) with zero extra dependencies — no Ollama, no model pull. Recorded
  from a loopback Ollama run of `qwen2.5:1.5b` (temperature 0.0, seed 42);
  integrity-checked at load, never presented as a current live-model result.
- `--timeout` flag (seconds) on `demo --live` and `serve`, plus the
  `LITTLE_CANARY_TIMEOUT` environment variable. The default per-call canary
  timeout is now 600 s (was a hardcoded 10 s), so `demo --live` can complete
  on CPU-only hardware where a single canary call takes minutes.
- Ollama-unreachable demo errors now name the fix: install command, `ollama
  serve`, and the exact `ollama pull <model>` to run.

### Changed

- README quick start leads with the offline demo; the Ollama install +
  `ollama pull` path is documented as the "go live" upgrade with exact
  commands. All relative repo links are now absolute GitHub URLs so every link
  resolves for the PyPI stranger.
- `little-canary serve` accepts `--timeout` and passes it through as the
  pipeline's canary timeout.
- A timeout-induced DEGRADED now names the knob to turn: the `demo --live`
  case detail and the `serve` `/check` canary-layer details cite `--timeout`
  / `LITTLE_CANARY_TIMEOUT` (or `canary_timeout` on `SecurityPipeline`) and
  the configured per-call timeout seconds.

## [0.3.10] - 2026-09-26

Patch release of the fixes reviewed and merged in [PR #112](https://github.com/hermes-labs-ai/little-canary/pull/112). The default canary, detector rules, and fail-open routing are unchanged.

- The OpenAI-compatible canary adapter now marks length-limited and other incomplete responses as degraded coverage instead of treating them as complete. It reports bounded failure reasons for malformed, empty, timed-out, and failed calls. The Hermes Agent bundle carries the same behavior.
- Paired benchmark summaries and the dashboard no longer present positive and benign-control cases as one pooled accuracy percentage; the separate case counts remain available.
- The JailBench-derived probe points to its repository license file.

This patch does not establish a new detection or false-block rate. The known limitations in 0.3.9 still apply.

## [0.3.9] - 2026-09-26

This release makes the package's `requests` range compatible with Hermes
Agent's core pin and includes the focused directory plugin admitted to the
Nous Research catalog at its pinned source revision. It adds model selection
and coverage diagnostics without changing the default canary or detector rules.

### Added

- Local exercise of Qwen3.5 2B, Liquid LFM2.5 1.2B, and Gemma 3 1B through
  the CLI, Python pipeline, and Hermes Agent model-selection paths. The
  default remains `qwen2.5:1.5b`.
- Case-level headless benchmark runs with fixed IDs, independent pipeline,
  model-only, and structural-only modes, coverage-aware denominators, and
  separate layer latency. The auxiliary JailBench-derived five-pair regression
  probe is selected explicitly and keeps its positive and benign-control
  results separate from the original corpus.
- Bounded `coverage_reason` diagnostics for failed canary or analysis coverage,
  including output-limit and timeout failures, without changing fail-open
  routing or treating incomplete calls as clean.
- Native OpenClaw plugin (`plugins/openclaw`) using the typed
  `before_agent_run` gate on supported embedded and CLI runners. It sends only
  the current prompt to the existing loopback HTTP adapter, blocks only an
  explicit unsafe verdict, and passes through with a sanitized warning when
  screening is unavailable, invalid, or degraded. The README and host matrix
  state the required service/config setup and runner limits.
- Host capability matrix: `docs/host-capability-matrix.json` records, per host
  version, where a prompt is intercepted, whether that host allows refusing it,
  what this repository ships for it, and the evidence for each answer.
  `docs/host-capability-matrix.md` is its prose form and
  `tests/test_host_capability_matrix.py` enforces it offline against the shipped
  manifests and adapters. Inbound prompt screening and outbound tool-execution
  blocking are recorded as separate capabilities and are never merged into one
  claim.
- Codex CLI certification. Codex CLI 0.154.0 loads the existing
  `plugins/claude-code` directory: it reads Claude-shaped `hooks/hooks.json`,
  resolves `CLAUDE_PLUGIN_ROOT`, and its `UserPromptSubmit` command output
  schema accepts `{"decision": "block", "reason": ...}`. The install route was
  exercised at 0.3.8. Interception itself was **not** observed: Codex gates hook
  execution behind an explicit trust approval, and in a headless run an
  unapproved hook was skipped silently while the prompt proceeded. The matrix
  row therefore remains `runtime_certified: false`.
- GitHub Copilot certification, as a negative result. Copilot CLI 1.0.84-5
  exposes `userPromptSubmitted`, whose output carries `modifiedPrompt`,
  `additionalContext`, and `suppressOutput` and no decision field: a hook can
  rewrite or annotate a prompt but cannot refuse it. Little Canary therefore
  ships no Copilot artifact, and a test asserts none appears.

### Changed

- The Hermes Agent directory plugin now installs from
  `integrations/hermes-agent` so its install scan covers runtime code without
  benchmark fixtures. The old repository-root install path is retired.
- The structural signal formerly displayed as
  `Direct injection: ignore previous instructions` is now displayed as
  `Direct injection (instruction override)` in verdicts and audit records.
  Consumers matching signal text should update that label.
- The `requests` dependency range now admits Hermes Agent's core pin while
  keeping a bounded upper limit.
- README and plugin descriptions now distinguish installed host support from
  observed runtime interception.

### Known limitations

- The default canary, analyzer rules, structural rules, and 256-token output
  ceiling are unchanged. Quoted attack phrases in security reports can still
  block, and a benign canary acknowledgement can still match `persona_shift`.
  Proposed exceptions failed independent attack checks and were not adopted.
- A degraded canary result is an inspection gap. Raising the output ceiling
  improved coverage on a small development screen but increased tail latency;
  no retry or shorter-answer policy is enabled by default.
- The original external TensorTrust corpus has not been rerun across the new
  model choices. This release does not establish a lower false-block rate.

## [0.3.8] - 2026-09-18

Packages the Claude Code plugin manifest at the location the Agent Plugins
v1.0.0 specification reads, so the plugin resolves for hosts outside Claude
Code. No detection, routing, or hook behavior changes.

### Added

- `plugins/claude-code/plugin.json`: an Agent Plugins v1.0.0 manifest at the
  plugin root, carrying the `$schema` identifier and the fields that
  specification allows. Claude Code continues to read
  `plugins/claude-code/.claude-plugin/plugin.json`, which is unchanged apart
  from the version bump; the two manifests are held in agreement by
  `tests/test_claude_code_plugin.py`.

## [0.3.7] - 2026-09-12

Publishes the Hermes Agent plugin that merged to `main` after `0.3.6` and was
therefore not installable from PyPI.

### Added

- Opt-in plugin for the Hermes Agent framework (`hermes-agent`, Nous Research),
  `little_canary.hermes_agent_plugin`, published through the
  `hermes_agent.plugins` entry point. The host still has to enable it in its
  `plugins.enabled` allow-list. It screens the turn's user message once at
  `pre_llm_call`, annotates `FLAG`, `BLOCK`, and `DEGRADED` turns, and
  withdraws tool authority at `pre_tool_call` only for a genuine `BLOCK`. The
  hook cannot stop prompt delivery: a blocked turn still reaches the model,
  annotated, without its tools. Verified against `hermes-agent` 0.19.0 (#74).

### Fixed

- Hermes Agent plugin turn keys require both ids and are unambiguous, capacity
  eviction can no longer release a live `BLOCK`, and `blocking_dispositions`
  accepts only `BLOCK`, so degraded screening cannot fail closed (#75).
- An unusable configured checker is reported as `DEGRADED` instead of leaving
  the turn unrecorded, and context truncation keeps the disposition guidance.

### Changed

- Repository standards, OpenSSF Scorecard, and Software Heritage archival
  workflows (#71, #72, #73).

Adapters remain opt-in. This release does not change detection logic,
benchmark claims, or the fail-open routing contract.

## [0.3.6] - 2026-09-09

Publishes the native host integrations that were merged to `main` after
`0.3.5` and were therefore not installable from PyPI.

### Added

- Optional native OpenAI Agents SDK input guardrail
  (`little_canary.openai_agents`), installed with the `openai-agents` extra.
  It maps screening results to safe, unsafe, and degraded outcomes, keeps the
  documented fail-open default with an explicit opt-in fail-closed policy, and
  the core package still imports without the SDK installed.
  `examples/openai_agents_example.py` shows the wiring.
- Claude Code plugin under `plugins/claude-code` plus the repository
  marketplace manifest `.claude-plugin/marketplace.json`. The
  `UserPromptSubmit` hook calls the local blocking-mode server and denies the
  turn when the prompt is rejected. The hook script uses only the standard
  library and refuses non-loopback endpoints.
- Hermes Gate repository rail (`.hermes/gate.toml`,
  `.hermes/hermes_gate_runner.py`) and the `hermes-quality` workflow, with
  runner tests in `tests/test_hermes_gate_runner.py`.

### Changed

- `little-canary serve` validates the requested port range and reports an
  explicit error instead of failing later in the socket bind.
- The LintLang CI workflow pin moved from `0.5.0` to `0.5.3`.

Adapters remain opt-in. This release does not change detection logic,
benchmark claims, or the fail-open routing contract.

## [0.3.5] - 2026-09-02

### Added

- Added a native Gemini CLI `BeforeAgent` extension that calls the local
  blocking-mode server and denies unsafe prompts before model execution.
- Added explicit, visible fail-open behavior for unavailable or degraded
  screening, with an opt-in fail-closed policy.

The copied-install contract was exercised against Gemini CLI 0.32.1 for both
pre-model denial and visible unavailable-server continuation. This integration
does not replace least privilege or tool policy.

## [0.3.4] - 2026-08-18

Post-`0.3.3` maintenance release. No product behavior changes.

### Added

- CI package-smoke job on Python 3.12 for pull requests and `main`: builds the
  sdist and wheel, runs `twine check`, then installs the exact wheel and the
  exact sdist independently in fresh virtual environments and verifies import,
  `__version__`, and `little-canary --version`.

### Changed

- Dependency floors refreshed via post-`0.3.3` maintenance (setuptools and
  requests with Python 3.9 markers; mypy allowed below 3), workflow action
  references pinned to immutable commit SHAs, the PyPI publishing identity
  isolated from the build job, and Python 3.13 declared in the package
  classifiers with CI source-compatibility validation.
- Stable CodeMeta software metadata added and linked with the Behavioral
  Canarying technical-note DOIs.
- Source release surfaces (`pyproject.toml`, `little_canary/__init__.py`,
  `CITATION.cff`, `.zenodo.json`, `codemeta.json`) advanced to `0.3.4`, and
  the README now points to GitHub Releases and PyPI as the live authorities
  on publication state instead of asserting current registry contents.

## [0.3.3] - 2026-07-25

The package, source metadata, and documented `demo` commands are `0.3.3`.
GitHub `v0.3.1` was source-only, PyPI remained on `0.3.0` until this release,
and `0.3.2` was not published and is not reused.

### Added

- Explicit `little-canary demo --replay` and `--live` command paths with distinct evidence, model, egress, and exit-state reporting; replay fails unavailable until a complete live capture is admitted.
- Machine-readable coverage state: routing (`safe`) is separate from `degraded`, `canary_status`, `analysis_method`, and `analysis_status`.
- Explicit failed/skipped layer states; distinct degraded and unexercised callback paths; and `DEGRADED`, `STRUCTURAL_ONLY`, or `UNSCREENED` propagation through guard and audit records.

### Fixed

- Failed or protocol-invalid canary/judge coverage no longer appears as risk `0`, PASS, or “passed all layers”; fail-open routing remains available with risk unset.
- Provider HTTP success now requires valid non-empty model content, and provider errors are bounded and redacted.
- Default pipeline layer snapshots retain signal categories and scores but omit raw canary responses and signal-evidence excerpts before callbacks or serialization.
- The HTTP adapter no longer skips one-to-five-character inputs or silently truncates attack suffixes; malformed, empty, and oversized requests are explicit errors.
- Version and organization metadata are coherent, and an unrelated DOI has been removed.
- CI installs the declared development tool set instead of carrying a second
  Ruff pin; mypy stays below version 2 while the project configuration targets
  Python 3.9; and the Python 3.10+ `pip-audit` tool is excluded only from
  Python 3.9 development environments.

### Documentation

- The primary `0.3.3` README and metadata no longer present historical benchmark rates, universal latency, universal determinism, local-only processing, or operating-system sandboxing as established facts.
- Replay is recorded analyzer evidence only when an admitted fixture is packaged, not a current model call; this release contains no such fixture. Remote backends receive raw input; an optional judge receives raw input plus canary output.

## [0.3.1] - 2026-05-31

GitHub source release and maintenance update. No `0.3.1` artifact was published to PyPI; the registry remained on `0.3.0`. Citation metadata was corrected on `main` after the tag.

## [0.3.0] - 2026-03-22

### Added
- **`little-canary serve` CLI command** — persistent HTTP server mode for low-latency detection (~75ms vs 300-1200ms cold-start). Keeps the `SecurityPipeline` warm in memory.
- **REST API endpoints** — `POST /check` (analyze text) and `GET /health` (pipeline status).
- **`little_canary.server` module** — `run_server()` and `create_server()` functions for programmatic use and embedding.
- **`little_canary.cli` module** — CLI dispatcher with `serve` subcommand (extensible for future commands).
- **Console script entry point** — `pip install little-canary` now provides the `little-canary` command.

### Changed
- Bumped version to 0.3.0.

## [0.2.3] - 2026-03-08

### Added
- `AuditLogger` — JSONL audit logging for every pipeline check. Writes `canary-audit.jsonl` (all checks) and `canary-alerts.jsonl` (blocked/flagged only). Input is stored as SHA-256 hash only, never raw text.
- `CanaryGuard` — trust-aware wrapper around `SecurityPipeline`. Three trust tiers: TRUSTED (owner, advisory-only, never blocked), KNOWN (flagged, not passed), UNKNOWN (blocked). Override mechanism with rate limiting (5/hr).
- Callback hooks on `SecurityPipeline`: `on_block`, `on_flag`, `on_pass` — exception-safe, never crash the pipeline.
- `audit_log_dir` parameter on `SecurityPipeline` for automatic per-check logging.

## [0.2.2] - 2026-03-02

### Changed
- Updated project URLs for PyPI backlinks

## [0.2.1] - 2026-03-02

### Fixed
- Standardized package metadata (author: Hermes Labs, email: lpcisystems@gmail.com)
- Added PyPI version badge to README
- Removed internal product branding from examples and benchmarks
- Updated benchmark results in README (TensorTrust 99.0%)

## [0.2.0] - 2026-02-25

### Added
- **TensorTrust benchmark** — 99.0% detection rate on 400 real-world prompt injection attacks (Claude Opus as production LLM)
- **Multi-model benchmark support** — tested canary pipeline across multiple models; 94.8% detection with 3B local model
- **Multi-model comparison view** on [littlecanary.ai](https://littlecanary.ai) website
- **PyPI publishing** — `pip install little-canary` now available

## [0.1.0] - 2026-02-21

Initial open source release.

### Added
- **Structural filter** — regex + decode-then-recheck for base64, hex, ROT13, reverse-encoded payloads
- **Canary probe** — sacrificial LLM behavioral analysis with repeatability controls
- **Behavioral analyzer** — dual-strategy detection (reaction patterns + output patterns)
- **LLM judge** (experimental) — optional second model to classify canary output
- **Three deployment modes** — block, advisory, full
- **Advisory system** — security prefix for production LLM system prompts
- **Benchmark suite** — 180-prompt test suite (160 adversarial, 9 categories) + 40 false positive prompts
- **Dashboard** — live browser dashboard for red team testing
- **Full pipeline test** — end-to-end with production LLM compliance measurement
- **Integration examples** — chatbot, email agent, generic
- **OSS documentation** — README, CLAUDE.md, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates

### Security
- Tightened `requests` dependency to `>=2.32.2` (CVE-2024-35195)
- Dashboard server binds to localhost only (`127.0.0.1`)
- Licensed under Apache 2.0 (patent grant for AI tooling)

### Historical benchmarks

The figures below were reported by the original release and are retained as history, not revalidated `0.3.3` claims. See the current benchmark documentation for limitations.
- 98% effective detection (full pipeline: canary + production LLM)
- 37% standalone block rate (canary + structural filter alone)
- 0% false positive rate on realistic chatbot traffic (0/40)
- ~250ms latency per check
