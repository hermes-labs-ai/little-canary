---
name: little-canary
description: Use when you need to screen inbound untrusted text before it reaches a primary model — detecting prompt injection by its behavioral effect on a sacrificial canary model, not just pattern matching — and want a block/flag/pass routing decision plus explicit behavioral-coverage state. Inbound preflight sensor, not a guarantee.
license: Apache-2.0
compatibility: Requires Python 3.9+; installs via `pip install little-canary` or runs standalone via `uvx little-canary`. Live demo mode needs a local Ollama instance; replay mode needs no network.
---

# little-canary

little-canary detects prompt injection by its effect on a sacrificial canary
model, not just pattern matching: untrusted input hits a powerless model
first, a behavioral check reads the residue, and it returns block, flag, or
pass before your primary model acts. Inbound preflight sensor, not a
guarantee.

## Use it for

- Screening inbound untrusted text before it reaches a main model
- Combining structural pattern checks with sacrificial-canary behavior checks
- Getting a routing decision (block/flag/pass) plus an explicit
  behavioral-coverage state (`REPLAY`, `LIVE`, `MOCK`, `STATIC_ONLY`)
- Running a local HTTP detection server in front of an agent's input path

## Do not use it for

- A guarantee that prompt injection is impossible
- A replacement for runtime containment controls
- A benchmark suite

## Quickstart

```bash
pip install little-canary
little-canary demo --replay
```

Or without installing, via [uv](https://docs.astral.sh/uv/):

```bash
uvx little-canary demo --replay
```

Real output (no packaged replay fixture admitted in this environment):

```
RUN_KIND   REPLAY
MODEL_CALL no — recorded output
CANARY     NOT EXERCISED THIS RUN
EGRESS     none
REPLAY     UNAVAILABLE
DETAIL     no admitted replay fixture is packaged
```

Live contrast against a local Ollama backend:

```bash
uvx little-canary demo --live --backend ollama --model qwen2.5:1.5b
```

## Output shape

- `demo --replay`: verifies analyzer behavior only when admitted response
  bytes are packaged; otherwise exits `REPLAY UNAVAILABLE` — unavailable
  replay is never evidence that input is safe
- `demo --live`: exercises the fixed synthetic contrast against loopback
  Ollama and binds the result to one backend, model digest, runtime, and
  configuration
- `serve`: persistent HTTP detection server; returns a verdict object with
  safety, degradation, canary/analysis status, summary, risk, and optional
  advisory text
- `--json`: emits the stable `little-canary-demo/v1` schema

## Common gotchas

- `REPLAY` verifies analyzer behavior only when admitted response bytes are
  packaged; an unavailable replay result must not be read as "input is safe."
- Replay never calls a model — it is bytes-in, verdict-out.
- Remote backends receive raw input; a configured judge receives raw input
  plus canary output.

## More

Full docs and CLI reference: https://github.com/hermes-labs-ai/little-canary
