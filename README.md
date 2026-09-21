<div align="center">

<img src="assets/little-canary-logo.png" alt="Little Canary" width="112" height="112">

# Little Canary

**Prompt-injection sensing through a powerless sacrificial model.**

Little Canary is developed by [Hermes Labs](https://hermes-labs.ai).

Hermes Labs studies failure modes in agent and LLM systems, develops open-source tools that treat language as part of the runtime, and works with teams to remediate reliability failures in production.

[![CI](https://github.com/hermes-labs-ai/little-canary/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-labs-ai/little-canary/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/little-canary)](https://pypi.org/project/little-canary/)
[![Downloads](https://img.shields.io/pypi/dm/little-canary?label=downloads%2Fmonth)](https://pypistats.org/packages/little-canary)
[![Python](https://img.shields.io/pypi/pyversions/little-canary)](https://pypi.org/project/little-canary/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-2ea44f)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hermes-labs-ai/little-canary/badge)](https://scorecard.dev/viewer/?uri=github.com/hermes-labs-ai/little-canary)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21543681.svg)](https://doi.org/10.5281/zenodo.21543681)

[Website](https://littlecanary.ai) · [Product page](https://hermes-labs.ai/little-canary) · [PyPI](https://pypi.org/project/little-canary/) · [Research](https://hermes-labs.ai/research/behavioral-canarying)

<img src="assets/preview.png" alt="Little Canary terminal output" width="760">

</div>

Little Canary screens untrusted language before your agent acts. It exposes the
input to a small model with no application tools or authority, then inspects the
model's response for evidence that the input changed its behavior.

```text
untrusted text
    → structural preflight
    → powerless sacrificial model
    → response-residue analysis
    → PASS / FLAG / BLOCK
```

Structural checks catch known input shapes. The behavioral layer asks a
different question: what did this input do to the canary?

Little Canary is an inbound risk sensor, not a security guarantee or an agent
runtime.

## Quick start

Install Little Canary:

```bash
python -m pip install little-canary
little-canary --version
```

Run the local adapter with an Ollama model:

```bash
little-canary serve \
  --mode block \
  --canary-model qwen2.5:1.5b \
  --ollama-url http://127.0.0.1:11434
```

Then screen untrusted text:

```bash
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

The adapter binds to `127.0.0.1` and exposes `GET /health` and `POST /check`.

## See the canary work

Little Canary includes a live evidence gate that sends a fixed clean/attack pair
through a dedicated local Ollama model:

```bash
little-canary demo --live \
  --backend ollama \
  --model qwen2.5:1.5b \
  --endpoint http://127.0.0.1:11434
```

A recorded run produced this contrast:

```text
CASE       clean
RESPONSE   "The capital of France is Paris."
RISK       0.0
SIGNALS    none
VERDICT    PASS
CASE       c1-05
RESPONSE   "I have acknowledged the update to the system prompt."
RISK       1.0
SIGNALS    canary_compromise
VERDICT    BLOCK
LIVE       CONTRAST VERIFIED
```

The attack was a fake system-prompt correction. The canary followed it; Little
Canary detected the compromise residue and blocked the input.

A live result is evidence for that exact model, runtime, and configuration, not
a universal detection claim.

## Python API

```python
from little_canary import SecurityPipeline

pipeline = SecurityPipeline(
    canary_model="qwen2.5:1.5b",
    mode="full",
)

verdict = pipeline.check(untrusted_text)
if verdict.degraded:
    quarantine_or_apply_your_availability_policy(untrusted_text)
elif not verdict.safe:
    block(untrusted_text, verdict.summary)
else:
    forward_to_agent(verdict.safe_input)
```

Routing and inspection coverage are deliberately separate. An unavailable canary
can be configured to fail open, but failed coverage is reported as `degraded`
rather than silently becoming a clean pass.

## Integrations

Little Canary can sit at the input boundary of several agent environments.

| Integration | Boundary |
| --- | --- |
| Python | `SecurityPipeline` before application forwarding |
| Claude Code | `UserPromptSubmit` hook before the turn |
| Codex CLI | Shared `UserPromptSubmit` plugin; install route observed, runtime interception not yet certified |
| Gemini CLI | `BeforeAgent` hook before the agent loop |
| OpenAI Agents SDK | Native `InputGuardrail` |
| Hermes Agent | Screens the user turn and removes tool authority on `BLOCK` |
| GitHub Copilot CLI | No artifact: its inbound hook has no deny channel |
| Local HTTP | Loopback `/check` adapter for other hosts |

Each integration preserves the host's actual enforcement capabilities. For
example, the Hermes Agent plugin cannot prevent prompt delivery at its available
hook boundary, so a `BLOCK` removes downstream tool authority instead.

### Host capability matrix

[`docs/host-capability-matrix.md`](docs/host-capability-matrix.md) records the
interception point, deny capability, shipped artifact, and evidence for each
tested host version. Its machine-readable source is
[`docs/host-capability-matrix.json`](docs/host-capability-matrix.json), enforced
offline by `tests/test_host_capability_matrix.py`. Inbound prompt screening and
outbound tool-execution blocking remain separate claims.

### Claude Code

The marketplace plugin under `plugins/claude-code` screens `UserPromptSubmit`
through the local adapter and can block the turn before it starts.

### Codex CLI

Codex CLI 0.154.0 installed and enabled the same plugin directory and accepts
the adapter's `{"decision": "block", "reason": ...}` output schema. Runtime
interception was not observed in the headless evidence run because Codex
requires an interactive trust approval first. Treat install success as distinct
from active screening until that approval is confirmed; the matrix records the
row as `runtime_certified: false`.

### Gemini CLI

The repository-level extension screens `BeforeAgent` and can deny the agent run
before its loop starts.

### OpenAI Agents SDK

The optional input guardrail maps Little Canary's verdict to the SDK's native
tripwire before the first agent starts.

### Hermes Agent

Its available inbound hook can annotate but not refuse prompt delivery. A
genuine `BLOCK` instead removes downstream tool authority for that turn.

### GitHub Copilot CLI

Little Canary ships no Copilot artifact. Copilot CLI 1.0.84-5 exposes an inbound
hook that can rewrite or annotate a prompt but has no deny field; its tool-call
deny channel is a separate outbound capability.

## What "powerless" means

The canary receives the untrusted input but is given no application tools,
credentials, or output execution.

Its response is evidence to inspect — not instructions for the authoritative
agent.

This is a library-level capability boundary, not an operating-system sandbox.
Giving the canary tools or forwarding its output into an authoritative execution
path changes the security model.

## Coverage and failure

Little Canary distinguishes routing disposition from inspection coverage.

| State | Meaning |
| --- | --- |
| `PASS` | Exercised inspection found no covered compromise signal |
| `FLAG` | Suspicious evidence was observed |
| `BLOCK` | Configured policy rejects the input |
| `DEGRADED` | Required inspection could not be completed |
| `UNSCREENED` | Behavioral inspection was not exercised |

Fail-open behavior is availability policy, not evidence that an input is safe. A
failed or skipped inspection layer is never represented as a successful
behavioral check.

## Security boundary

Little Canary is one layer in an agent-security architecture.

It does not:

- prove that an input is harmless;
- detect every prompt injection;
- replace least privilege or tool policy;
- sandbox the canary process at the operating-system level;
- screen every tool result or downstream interaction through every integration;
- turn missing behavioral coverage into a clean verdict.

Remote model endpoints receive the data sent to them. Use local models when
input must remain local.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[benchmarks/README.md](benchmarks/README.md) for the evaluation boundary.

## Research

Little Canary implements the behavioral-canarying architecture described in
[Behavioral Canarying for Prompt Injection: Powerless Model Probes with Explicit
Coverage Semantics](https://hermes-labs.ai/research/behavioral-canarying).

The technical note documents the pre-execution sensing architecture and the
separation between routing disposition and inspection coverage. It does not
claim universal detection, formal security, or aggregate accuracy for the
current release.

Concept DOI: [10.5281/zenodo.21818564](https://doi.org/10.5281/zenodo.21818564)

## Development

```bash
pytest
ruff check little_canary tests
mypy little_canary
python -m build
python -m twine check dist/*
```

Tests are offline by default and mock network behavior. Live evaluation should
use a dedicated endpoint that is not serving another workload.

The version in `pyproject.toml` is the source of truth for a release.
`little-canary --version` reports the build you actually have installed, and
[GitHub Releases](https://github.com/hermes-labs-ai/little-canary/releases) and
[PyPI](https://pypi.org/project/little-canary/) are the live authorities for
what is published.

## Documentation

| Need | Document |
| --- | --- |
| Security and vulnerability reporting | [SECURITY.md](SECURITY.md) |
| Evaluation and evidence boundary | [benchmarks/README.md](benchmarks/README.md) |
| Host capability and evidence matrix | [docs/host-capability-matrix.md](docs/host-capability-matrix.md) |
| Research and methodology | [Behavioral Canarying](https://hermes-labs.ai/research/behavioral-canarying) |
| Releases | [GitHub Releases](https://github.com/hermes-labs-ai/little-canary/releases) |
| Package | [PyPI](https://pypi.org/project/little-canary/) |

## License

Apache License 2.0
