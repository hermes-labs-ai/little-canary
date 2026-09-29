<div align="center">

# Little Canary

<img src="https://github.com/hermes-labs-ai/little-canary/raw/main/assets/little-canary-header.jpg" alt="Little Canary — prompt injection sensing through a sacrificial model" width="760">

**Screen untrusted prompts for signs of injection before your agent acts.**

Little Canary runs untrusted text through a powerless "canary" model first and watches what it does. A host integration can use the verdict to block the input or restrict downstream tool authority, depending on that host's capabilities.

[![PyPI](https://img.shields.io/pypi/v/little-canary)](https://pypi.org/project/little-canary/)
[![Python 3.9+](https://img.shields.io/pypi/pyversions/little-canary)](https://pypi.org/project/little-canary/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-2ea44f)](https://github.com/hermes-labs-ai/little-canary/blob/main/LICENSE)

[Quick start](#quick-start-2-minutes) · [Integrations](#put-it-in-front-of-your-agent) · [How it works](#the-idea) · [Research](#research) · [Website](https://littlecanary.ai)

</div>

---

## The problem

A prompt injection looks like ordinary data — a web page, an email, a tool result — until your agent follows the instructions hidden inside it. Pattern-matching filters can miss attacks that do not match known patterns. By the time you notice, the agent has already acted.

## The idea

Coal miners sent a canary in first. Little Canary does the same thing for agents:

1. **Send the untrusted text to a canary model** that has no tools, no credentials, and nothing to lose.
2. **Inspect the canary's response** for signs the input changed its behavior.
3. **Return a verdict** (`PASS`, `FLAG`, `BLOCK`) for the host to enforce within its available interception points.

Structural checks run alongside to catch known attack shapes. The canary can reveal attacks that no pattern check has catalogued yet.

<img src="https://github.com/hermes-labs-ai/little-canary/raw/main/assets/preview.png" alt="Little Canary screening output: clean input passes, injected input is blocked" width="760">

Little Canary is developed by [Hermes Labs](https://hermes-labs.ai).

## Quick start (2 minutes)

No model download needed. The offline demo ships with the package and runs with zero extra dependencies:

```bash
pip install little-canary
little-canary demo
```

You'll see one clean input → `PASS` and one injected input → `BLOCK`, with the recorded canary responses, the signals found, and the verdict for each. The offline replay verifies the analyzer against a packaged recorded capture — it makes no model call and no network call.

### Go live: run your own canary

The demo above replays a recorded capture. To screen with a real model on your machine, install Ollama, pull the small canary model (~986 MB download), and run the live contrast:

```bash
curl -fsSL https://ollama.com/install.sh | sh   # or see https://ollama.com/download
ollama serve                                     # separate terminal; serves on http://127.0.0.1:11434
ollama pull qwen2.5:1.5b
little-canary demo --live --backend ollama --model qwen2.5:1.5b --endpoint http://127.0.0.1:11434
```

The live demo sends the same clean/injected pair to your local canary and prints both responses, signals, and verdicts — so you can see whether the canary followed the attack and whether Little Canary caught it. On CPU-only hardware each of the two calls can take several minutes; the default per-call timeout is 600 s (override with `--timeout` seconds or the `LITTLE_CANARY_TIMEOUT` env var).

> Results depend on the canary model you run.

## Screen your own input

Start the local screening service:

```bash
little-canary serve --mode block --canary-model qwen2.5:1.5b --ollama-url http://127.0.0.1:11434
```

`serve` defaults to advisory mode (screen and report, never block); `--mode block` above opts into blocking explicitly. CPU-only machines can raise the per-call canary timeout with `--timeout` seconds or `LITTLE_CANARY_TIMEOUT` (default 600 s).

Send it anything untrusted:

```bash
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

The service binds to loopback only and exposes `GET /health`. Its JSON response exposes `safe`, `degraded`, `canary_status`, `analysis_status`, and optional `advisory` data. Read those fields before forwarding input; the disposition labels below summarize CLI and host behavior rather than a JSON `Result` field.

Python apps can skip HTTP and call `SecurityPipeline.check()` directly — see the [example integrations](https://github.com/hermes-labs-ai/little-canary/blob/main/examples/).

The default remains `qwen2.5:1.5b`. Select an installed model with `serve --canary-model`, `demo --model`, or Python's `SecurityPipeline(canary_model=...)`; the Hermes Agent plugin reads `LITTLE_CANARY_MODEL`. Locally exercised alternatives are `qwen3.5:2b-q4_K_M`, `LiquidAI/lfm2.5-1.2b-instruct:q4_k_m`, and `gemma3:1b`. Pull weights with `ollama pull <tag>` and check each model's license. These are selectable models, not performance guarantees; see the [evaluation guidance](https://github.com/hermes-labs-ai/little-canary/blob/main/benchmarks/README.md).

## Pre-screen a batch of documents or messages

`little-canary screen` (or `little_canary.batch.screen_batch`) runs the same pipeline once per item — nothing is aggregated into a batch-level "safe" verdict.

```bash
printf '%s\n' '{"id":"m1","source":"inbox","text":"Quarterly numbers attached."}' \
  | little-canary screen --mode full
```

Input is JSONL: each line is a JSON string or `{"text", "id"?, "source"?}`. Output is one `little-canary-batch/v1` JSON document with per-item `state` (`pass`, `flag`, `block`, `degraded`, `unexercised`), provenance (`index`, `id`, `source`, `sha256`, `length`) and the standard verdict. Item text is never echoed. An item whose check raises is `degraded`, never `pass`. Admission is all-or-nothing and happens before any check runs: malformed JSON, lone Unicode surrogates, non-string labels, or any breach of `--max-items` (default 1000), `--max-item-bytes` (UTF-8 bytes of one text, default 65536) or `--max-total-bytes` (all texts, default 8 MiB) rejects the whole batch — nothing is truncated. Lines are read in bounded chunks, so an oversized line is refused before it is fully allocated; `id`/`source` labels are capped at 256 characters. The pipeline's own `max_input_length` policy still applies per item. Exit status: `2` if the input is empty or invalid or any item is `degraded`/`unexercised` (a coverage hold is never masked by a block elsewhere in the batch); otherwise `1` if any item is `block`/`flag`; otherwise `0` (non-empty, every item `pass`). `pass` requires both the canary and analysis layers to have run. Screening is advisory input-risk sensing with the same coverage limits as a single check.

## Reading a verdict

| Verdict | Meaning | What to do |
| --- | --- | --- |
| `PASS` | Inspection ran and found no covered compromise signal. | Proceed. |
| `FLAG` | Suspicious structural or behavioral evidence was observed. | Log it, restrict tools, or ask a human. |
| `BLOCK` | Configured policy rejects the input. | Apply the host's documented blocking behavior. |
| `DEGRADED` / `UNSCREENED` | Behavioral inspection didn't complete or didn't run. | Treat as unscreened, not as clean. |

**Routing and coverage are separate.** A fail-open setup can let a turn continue while reporting degraded coverage. Don't mistake that for a behavioral pass.
Failed canary coverage can include a `coverage_reason` in the layer result, such as `output_limit` or `timeout`; this diagnostic does not change the verdict.

**Known false-block limitation:** quoted attack phrases in security reports can trigger a structural `BLOCK`; harmless canary acknowledgements can also trigger behavioral rules. In block mode, legitimate work can be blocked. Little Canary has no built-in pause-and-approve UI; hosts can use advisory routing and implement review where their interception point allows it. See the [host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md).

## Put it in front of your agent

Run the local service above, then wire in the host you use. Not every host lets a plugin refuse a prompt; the [host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md) records exactly what each one can intercept and block.

| Host | Integration | Can it block the turn? |
| --- | --- | --- |
| **Claude Code** | [Plugin](https://github.com/hermes-labs-ai/little-canary/blob/main/plugins/claude-code) screens `UserPromptSubmit` | Yes |
| **OpenCode** | [Plugin](https://github.com/hermes-labs-ai/little-canary/blob/main/plugins/opencode) flags submitted `chat.message` text | No — advisory warning only |
| **Pi** | [Extension](https://github.com/hermes-labs-ai/little-canary/blob/main/plugins/pi) screens submitted `input` | Yes — when the service returns an unsafe verdict |
| **Gemini CLI** | Extension screens `BeforeAgent` | Yes — denies the run before the loop starts |
| **OpenAI Agents SDK** | [Input guardrail](https://github.com/hermes-labs-ai/little-canary/blob/main/examples/openai_agents_example.py) maps verdicts to the SDK tripwire | Yes — before the first agent starts |
| **OpenClaw** | [Native plugin](https://github.com/hermes-labs-ai/little-canary/blob/main/plugins/openclaw), install below | Yes — current prompt only, not history or tool results |
| **Hermes Agent** | [Native plugin](https://github.com/hermes-labs-ai/little-canary/blob/main/integrations/hermes-agent/README.md) screens the user turn | No — a block removes downstream tool authority instead |

<details>
<summary>OpenClaw install</summary>

Install the native package from ClawHub after starting the local Little Canary
service in block mode. Review and accept the hook capability requested during
installation:

```bash
openclaw plugins install clawhub:@hermes-labs-ai/little-canary-openclaw
openclaw plugins enable little-canary-openclaw
openclaw config set plugins.entries.little-canary-openclaw.hooks.allowConversationAccess true
```

Review the conversation-access permission before enabling it. This package
supports the tested OpenClaw 2026.9.5–2026.9.6 host range and screens only the
current prompt on embedded and CLI agent runs. A source checkout can still use
`openclaw plugins install ./plugins/openclaw --force`. The package's
[install and boundary notes](https://github.com/hermes-labs-ai/little-canary/blob/main/plugins/openclaw/README.md) describe the fail-open
behavior and unsupported paths.
</details>

<details>
<summary>Hermes Agent install</summary>

With Hermes Agent 0.21.3 or later and local Ollama, install the reviewed community
[catalog entry](https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/little-canary.yaml):

```bash
ollama pull qwen2.5:1.5b
hermes plugins install little-canary
hermes plugins enable little-canary
hermes plugins list
```

The native plugin runs inside Hermes and does not need `little-canary serve`.
A BLOCK removes downstream tool authority; the original prompt still reaches
the model. If the catalog entry has not reached your client, use
`hermes plugins install hermes-labs-ai/little-canary/integrations/hermes-agent --no-enable`
and then enable it. See the [Hermes Agent guide](https://littlecanary.ai/docs/integrations/hermes-agent)
for verification, cache fallback, model selection, and hook limits.

</details>

## What Little Canary is and isn't

- **It's a sensing layer.** It sits alongside tool policy, sandboxing, and human review — it doesn't replace them.
- **The canary is powerless at the application layer,** not isolated by an OS sandbox.
- **A `PASS` means no covered signal was found in this inspection.** It doesn't mean the input is safe under every circumstance.
- **Detection rates depend on your model, your policy, and the attack.** [Benchmarks and methodology](https://github.com/hermes-labs-ai/little-canary/blob/main/benchmarks/README.md) show how we measure it and where it misses.

We'd rather you know the edges than find them in production.

## Research

The [behavioral canarying technical note](https://hermes-labs.ai/research/behavioral-canarying) explains the powerless-model probe and why a routing decision must stay separate from whether inspection actually ran.

## Contributing

Found an injection that got through? [Open an issue](https://github.com/hermes-labs-ai/little-canary/issues) with a safe reproducer and the observed result. For fixes or integrations, run the offline tests and Ruff, then open a pull request. The [contributor guide](https://github.com/hermes-labs-ai/little-canary/blob/main/CONTRIBUTING.md) has setup and submission details.

[Benchmarks](https://github.com/hermes-labs-ai/little-canary/blob/main/benchmarks/README.md) · [Host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md) · [Security policy](https://github.com/hermes-labs-ai/little-canary/blob/main/SECURITY.md) · [Releases](https://github.com/hermes-labs-ai/little-canary/releases)

## License

Apache-2.0. The source version lives in `pyproject.toml`; compare `little-canary --version` against [GitHub Releases](https://github.com/hermes-labs-ai/little-canary/releases) and [PyPI](https://pypi.org/project/little-canary/) for the published build.
