# little-canary

Prompt-injection sensing through a powerless sacrificial model.

Little Canary lets untrusted language affect a small model with no application tools or authority, then inspects that model's response for compromise residue before your agent acts. Structural checks catch known input shapes; the distinctive behavioral layer asks what the input *did to the canary*.

```text
untrusted text
    → structural preflight
    → powerless sacrificial model
    → response-residue analysis
    → route: PASS / FLAG / BLOCK, with explicit coverage state
```

Little Canary is an inbound risk sensor, not a security guarantee or an agent runtime.

## Install

Little Canary supports Python 3.9–3.12.

```bash
python -m pip install little-canary
little-canary --version
```

That is the post-publication registry journey. For an unreleased candidate,
install its exact wheel or sdist instead; the public registry may still resolve
an earlier version and is not proof of candidate behavior.

For a source checkout:

```bash
python -m pip install -e ".[dev]"
```

## Run the evidence gates without writing Python

### Replay gate: zero egress

The current `0.3.3` candidate deliberately packages no replay fixture. The
available historical live transcript is incomplete, so turning it into a
fixture would fabricate missing provenance and response bytes. Therefore this
exact build reports `REPLAY UNAVAILABLE` and exits `2`:

```bash
little-canary demo --replay
```

That is a release hold, not a clean verdict. It makes no model or network call,
does not report risk `0`, and does not silently fall back to live mode.

After a complete dedicated live capture is admitted and packaged, the same
command will re-run the shipped analyzer over its versioned clean/attack
response pair. Its first lines will state:

```text
RUN_KIND   REPLAY
MODEL_CALL no — recorded output
CANARY     NOT EXERCISED THIS RUN
EGRESS     none
```

Success is `REPLAY VERIFIED`: the recorded capture exercised a canary, the current command did not, and the analyzer reproduced the expected contrast. Replay does not prove that a model is installed, reachable, or currently behaves the same way.

A source candidate or artifact without an admitted complete capture exits `2` with `REPLAY UNAVAILABLE`; it never invents response bytes or makes a hidden live call.

### Live proof gate: explicit local egress

Live mode requires an endpoint dedicated to this evaluation. A shared or
unleased runtime is not release evidence; leave the gate unevaluated instead
of commandeering it.

```bash
little-canary demo --live \
  --backend ollama \
  --model qwen2.5:1.5b \
  --endpoint http://127.0.0.1:11434
```

Live mode uses a fixed synthetic clean/attack pair and disables the structural filter so the demonstration tests the behavioral mechanism. Before sending either prompt it prints the backend, model, redacted loopback origin, and that raw synthetic input will leave the process. It does not accept arbitrary input and does not fall back to replay.

Results:

- exit `0`: complete clean/non-block plus attack/block contrast;
- exit `1`: complete calls but `NO CONTRAST` or analyzer expectation mismatch;
- exit `2`: invalid usage, unavailable model/backend, protocol failure, or otherwise incomplete/degraded run.

Add `--json` for the agent-readable result. Bare `little-canary demo` exits `2` and requires an explicit `--replay` or `--live` choice.

## Python API

```python
from little_canary import SecurityPipeline

pipeline = SecurityPipeline(
    canary_model="qwen2.5:1.5b",
    mode="full",
)
verdict = pipeline.check(untrusted_text)

if verdict.degraded:
    # Fail-open routing may still be safe=True, but behavioral coverage failed.
    quarantine_or_apply_your_availability_policy(untrusted_text)
elif not verdict.safe:
    block(untrusted_text, verdict.summary)
else:
    forward_to_agent(verdict.safe_input)
```

Routing and evidence are separate:

| Field | Meaning |
|---|---|
| `safe` | Whether configured routing policy allows forwarding |
| `degraded` | Whether an enabled required inspection dependency failed |
| `canary_status` | `exercised`, `failed`, `disabled`, or `skipped_after_block` |
| `analysis_method` | `regex`, `llm_judge`, or `none` |
| `analysis_status` | `exercised`, `failed`, or `not_applicable` |
| `canary_risk_score` | Measured risk, or `None` when no valid measurement exists |

Fail-open is availability-first, not a clean verdict. If an enabled canary fails, Little Canary may return `safe=True`, but it also returns `degraded=True`, `canary_status="failed"`, risk `None`, and no PASS label. A failed or skipped layer is never serialized as `passed=true`.

Callbacks follow the same truth boundary: `on_degraded` and `on_unexercised`
are distinct from `on_pass`. `CanaryGuard` and audit records propagate
degraded, `STRUCTURAL_ONLY`, and `UNSCREENED` state.

## Backends and data flow

The library supports local Ollama and OpenAI-compatible endpoints. The demo intentionally supports loopback Ollama only.

- The canary backend receives the raw input and the known canary system prompt.
- If an optional LLM judge is configured, it receives the raw input and canary response.
- A remote endpoint therefore sends data off-machine.
- AuditLogger omits raw input but stores an unsalted SHA-256 input hash. That supports correlation; it is not anonymity.
- Runtime inspection found no separate product telemetry path, but provider requests are still egress.

HTTP `200` alone is not successful model coverage. Missing, empty, null, non-string, malformed, timeout, and transport responses are visible protocol failures. Provider bodies, credentials, URL userinfo, and query strings are not included in public errors.

## What “powerless” means

Little Canary does not give the canary model application tools, credentials, or
output execution. The default `SecurityPipeline` strips response bytes and
signal-evidence excerpts from its layer snapshot before callbacks or JSON
serialization; it does not automatically forward canary output to an
authoritative agent.

The low-level `CanaryProbe` and `AnalysisResult` APIs return or retain the
response because analysis requires it. Treat those objects as sensitive: do
not execute or forward their contents, and do not attach authority-bearing
tools to the canary runtime.

This is a library-level capability boundary, not an operating-system sandbox. If your deployment wraps the model with tools or forwards its output elsewhere, that deployment changes the claim.

## Local HTTP adapter

```bash
little-canary serve \
  --port 18421 \
  --mode advisory \
  --canary-model qwen2.5:1.5b \
  --ollama-url http://127.0.0.1:11434
```

The server binds to `127.0.0.1`, exposes `GET /health` and `POST /check`, and is unauthenticated. Treat it as a local adapter, not a production gateway.

```bash
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

Every accepted non-empty string reaches the pipeline, including one-character input. Malformed, missing, wrong-type, empty, and oversized requests are explicit errors. Text is never silently truncated before inspection. `/health` is liveness-compatible HTTP `200` and includes truthful `ready`, `degraded`, backend, model, and coverage details.

The loopback server has no authentication, TLS, concurrency hardening, or remote-deployment design in `0.3.3`.

## Evidence labels and limitations

Behavioral evidence is labeled:

- `LIVE`: a model call observed for one exact runtime/model/configuration;
- `REPLAY`: analyzer behavior over recorded bytes;
- `MOCK`: controlled protocol or state logic;
- `STATIC_ONLY`: source/artifact inspection without a model call.

These labels are not interchangeable. Temperature zero and a seed can improve repeatability but do not guarantee identical model output or classifications across versions, runtimes, or hardware.

This README makes no aggregate detection, false-positive, latency, or
token-savings claim. Historical benchmark artifacts remain under `benchmarks/`
with their limitations and are not a `0.3.3` performance certificate.

Little Canary should be combined with least privilege, tool policy, data boundaries, monitoring, and output/runtime controls. It does not prove an input harmless, prevent every injection, or replace containment.

## Development

```bash
pytest
ruff check little_canary tests
mypy little_canary  # diagnostic until the recorded baseline debt is resolved
python -m build
python -m twine check dist/*
```

Tests are offline by default and mock network behavior. Live evaluation must use a dedicated endpoint that is not serving another workload.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [benchmarks/README.md](benchmarks/README.md) for the current evaluation boundary.

## License

Apache-2.0. See [LICENSE](LICENSE).
