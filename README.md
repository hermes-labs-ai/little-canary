<div align="center">

# Little Canary

<img src="assets/little-canary-header.jpg" alt="Little Canary — prompt injection sensing through a sacrificial model" width="760">

**Catch prompt injection before your agent acts on it.**

Little Canary runs untrusted text through a powerless "canary" model first and watches what it does. If the text hijacks the canary, your real agent never sees it.

[![PyPI](https://img.shields.io/pypi/v/little-canary)](https://pypi.org/project/little-canary/)
[![Python 3.9+](https://img.shields.io/pypi/pyversions/little-canary)](https://pypi.org/project/little-canary/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-2ea44f)](LICENSE)

[Quick start](#quick-start-2-minutes) · [Integrations](#put-it-in-front-of-your-agent) · [How it works](#the-idea) · [Research](#research) · [Website](https://littlecanary.ai)

</div>

---

## The problem

A prompt injection looks like ordinary data — a web page, an email, a tool result — until your agent follows the instructions hidden inside it. Pattern-matching filters miss anything they haven't seen before. By the time you notice, the agent has already acted.

## The idea

Coal miners sent a canary in first. Little Canary does the same thing for agents:

1. **Send the untrusted text to a canary model** that has no tools, no credentials, and nothing to lose.
2. **Inspect the canary's response** for signs the input changed its behavior.
3. **Return a verdict** (`PASS`, `FLAG`, `BLOCK`) before your primary agent touches the input.

Structural checks run alongside to catch known attack shapes. The canary can reveal attacks that no pattern check has catalogued yet.

<img src="assets/preview.png" alt="Little Canary screening output: clean input passes, injected input is blocked" width="760">

Little Canary is developed by [Hermes Labs](https://hermes-labs.ai).

## Quick start (2 minutes)

Requires Python 3.9+ and a local [Ollama](https://ollama.com/) install.

```bash
pip install little-canary
ollama pull qwen2.5:1.5b
little-canary demo --live --backend ollama --model qwen2.5:1.5b --endpoint http://127.0.0.1:11434
```

The demo sends one clean input and one injected input through your local canary and prints both responses, the signals it found, and the verdict for each. You'll see whether the canary followed the attack and whether Little Canary caught it.

> Results depend on the canary model you run.

## Screen your own input

Start the local screening service:

```bash
little-canary serve --mode block --canary-model qwen2.5:1.5b --ollama-url http://127.0.0.1:11434
```

Send it anything untrusted:

```bash
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

The service binds to loopback only and exposes `GET /health`. Your application reads the verdict and decides what to do before forwarding the input.

Python apps can skip HTTP and call `SecurityPipeline.check()` directly — see the [example integrations](examples/).

## Reading a verdict

| Verdict | Meaning | What to do |
| --- | --- | --- |
| `PASS` | Inspection ran and found no covered compromise signal. | Proceed. |
| `FLAG` | Suspicious behavior observed. | Log it, restrict tools, or ask a human. |
| `BLOCK` | Configured policy rejects the input. | Don't forward it. |
| `DEGRADED` / `UNSCREENED` | Behavioral inspection didn't complete or didn't run. | Treat as unscreened, not as clean. |

**Routing and coverage are separate.** A fail-open setup can let a turn continue while reporting degraded coverage. Don't mistake that for a behavioral pass.

## Put it in front of your agent

Run the local service above, then wire in the host you use. Not every host lets a plugin refuse a prompt; the [host capability matrix](docs/host-capability-matrix.md) records exactly what each one can intercept and block.

| Host | Integration | Can it block the turn? |
| --- | --- | --- |
| **Claude Code** | [Plugin](plugins/claude-code) screens `UserPromptSubmit` | Yes |
| **Gemini CLI** | Extension screens `BeforeAgent` | Yes — denies the run before the loop starts |
| **OpenAI Agents SDK** | [Input guardrail](examples/openai_agents_example.py) maps verdicts to the SDK tripwire | Yes — before the first agent starts |
| **OpenClaw** | [Native plugin](plugins/openclaw), install below | Yes — current prompt only, not history or tool results |
| **Hermes Agent** | [Native plugin](integrations/hermes-agent/README.md) screens the user turn | No — a block removes downstream tool authority instead |

<details>
<summary>OpenClaw install</summary>

From a Little Canary checkout:

```bash
openclaw plugins install ./plugins/openclaw --force
openclaw plugins enable little-canary-openclaw
openclaw config set plugins.entries.little-canary-openclaw.hooks.allowConversationAccess true
```

Review the conversation-access permission before enabling it.
</details>

## What Little Canary is and isn't

- **It's a sensing layer.** It sits alongside tool policy, sandboxing, and human review — it doesn't replace them.
- **The canary is powerless at the application layer,** not isolated by an OS sandbox.
- **A `PASS` means no covered signal was found in this inspection.** It doesn't mean the input is safe under every circumstance.
- **Detection rates depend on your model, your policy, and the attack.** [Benchmarks and methodology](benchmarks/README.md) show how we measure it and where it misses.

We'd rather you know the edges than find them in production.

## Research

The [behavioral canarying technical note](https://hermes-labs.ai/research/behavioral-canarying) explains the powerless-model probe and why a routing decision must stay separate from whether inspection actually ran.

## Contributing

Found an injection that got through? [Open an issue](https://github.com/hermes-labs-ai/little-canary/issues) with a safe reproducer and the observed result. For fixes or integrations, run the offline tests and Ruff, then open a pull request. The [contributor guide](CONTRIBUTING.md) has setup and submission details.

[Benchmarks](benchmarks/README.md) · [Host capability matrix](docs/host-capability-matrix.md) · [Security policy](SECURITY.md) · [Releases](https://github.com/hermes-labs-ai/little-canary/releases)

## License

Apache-2.0. The source version lives in `pyproject.toml`; compare `little-canary --version` against [GitHub Releases](https://github.com/hermes-labs-ai/little-canary/releases) and [PyPI](https://pypi.org/project/little-canary/) for the published build.
