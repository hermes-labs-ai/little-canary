---
name: little-canary
description: Use when an agent needs to check untrusted text for prompt injection before acting on it — screening tool output, a fetched page, or a user-supplied document by exposing it to a powerless sacrificial model and inspecting the response for compromise, rather than pattern-matching alone. Local Ollama or OpenAI-compatible backend, no MCP.
license: Apache-2.0
compatibility: Requires Python 3.9+; installs via pip. Needs a local Ollama (or OpenAI-compatible) backend for the canary model call; the local HTTP adapter binds to 127.0.0.1 only.
---

# Little Canary

Little Canary lets untrusted text affect a small, powerless sacrificial model
first, then inspects that model's response for compromise residue before an
agent acts on the text. Structural checks catch known input shapes; the
distinctive behavioral layer asks what the input *did to the canary*. It is a
plain local HTTP adapter, not an MCP server.

## Use it for

- Screening a fetched web page, tool result, or user-supplied document for
  prompt injection before forwarding it to the primary agent
- Running the replay or live evidence gate to see PASS/FLAG/BLOCK verdicts on
  a clean vs. injection-shaped input pair
- Standing up the local `little-canary serve` adapter and calling
  `POST /check` before a prompt reaches the model
- Checking one untrusted text string via the Python `SecurityPipeline` API

## Do not use it for

- A security guarantee, formal proof, or replacement for least privilege and
  tool policy
- Proving an input is harmless — a `PASS` verdict is inspection coverage, not
  a certificate
- Screening tool outputs after the fact — it screens the exact text you hand
  it, not the agent's downstream actions

## Quickstart

```bash
python -m pip install little-canary
little-canary --version
```

Run the zero-egress replay gate (works with no model or network call once a
capture is admitted; the current release reports `REPLAY UNAVAILABLE`):

```bash
little-canary demo --replay
```

Run the live evidence gate against a local Ollama backend:

```bash
little-canary demo --live \
  --backend ollama \
  --model qwen2.5:1.5b \
  --endpoint http://127.0.0.1:11434
```

Start the local HTTP adapter and check one string:

```bash
little-canary serve --port 18421 --mode advisory \
  --canary-model qwen2.5:1.5b --ollama-url http://127.0.0.1:11434
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

## Output shape

- `demo --replay` / `demo --live`: exit `0` (contrast verified), `1` (no
  contrast or mismatch), or `2` (invalid usage, unavailable backend, or
  degraded run); add `--json` for machine-readable output
- `POST /check`: JSON verdict with `safe`, `degraded`, `canary_status`,
  `analysis_method`, and `canary_risk_score`
- `GET /health`: liveness plus truthful `ready`/`degraded`/coverage fields

## Common gotchas

- Fail-open is availability-first, not a clean verdict: a failed or skipped
  canary can still return `safe=True` alongside `degraded=True` — check both
  fields, not `safe` alone.
- The `demo` command requires an explicit `--replay` or `--live` choice; a
  bare `little-canary demo` exits `2`.
- The local server is unauthenticated loopback-only (`127.0.0.1`) with no
  TLS — treat it as a local adapter, not a production gateway.
- This is a plain local HTTP service, not an MCP server.

## More

Full docs and CLI reference:
https://github.com/hermes-labs-ai/little-canary
