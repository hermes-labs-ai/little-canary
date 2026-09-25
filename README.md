<div align="center">

# Little Canary

<img src="assets/little-canary-header.jpg" alt="Little Canary — detection sensing through a sacrificial model" width="760">

**See what untrusted text does to a powerless model before your agent acts on it.**

by [Hermes Labs](https://hermes-labs.ai)

[Website](https://littlecanary.ai) · [PyPI](https://pypi.org/project/little-canary/) · [Integrations](#put-it-in-front-of-an-agent) · [Research](https://hermes-labs.ai/research/behavioral-canarying)

</div>

A prompt injection can look like ordinary task data until an agent follows it. Little Canary sends that input to a separate canary model with no application tools or credentials, then inspects its response for signs the input changed the model's behavior. Structural checks also catch known attack shapes. Your application gets a screening result before deciding what the primary agent may do.

<img src="assets/preview.png" alt="Little Canary screening output" width="760">

## See the canary work

Install [Ollama](https://ollama.com/), start it locally, and pull the small model used by the live demo. Little Canary supports Python 3.9+.

```bash
python3 -m pip install little-canary
ollama pull qwen2.5:1.5b
little-canary demo --live --backend ollama --model qwen2.5:1.5b \
  --endpoint http://127.0.0.1:11434
```

The demo sends a fixed clean/attack pair through your local canary. Look for the two responses, the signals, and the resulting verdicts. The result tells you whether the canary followed the attack and whether Little Canary detected it. Live outcomes depend on the model and setup you run.

## Screen your own input

Run the local screening service in one terminal:

```bash
little-canary serve --mode block --canary-model qwen2.5:1.5b \
  --ollama-url http://127.0.0.1:11434
```

Then call it from another:

```bash
curl -sS http://127.0.0.1:18421/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"untrusted text"}'
```

The service binds to loopback and also exposes `GET /health`. Your application decides how to handle its result before forwarding the input. A clean verdict means no covered compromise signal was found in this inspection, not that the input is safe under every circumstance.

Python applications can call `SecurityPipeline.check()` directly; see the [example integrations](examples/) for an application-level wiring pattern.

## Put it in front of an agent

Little Canary ships host integrations for Claude Code, Gemini CLI, OpenClaw, OpenAI Agents SDK, and Hermes Agent, as well as the Python API and local HTTP service. The [host capability matrix](docs/host-capability-matrix.md) tells you where each integration intercepts input and what it can actually block. Start from the [Claude Code plugin](plugins/claude-code), [OpenClaw plugin](plugins/openclaw), or [Hermes Agent guide](integrations/hermes-agent/README.md) for their install paths.

Host boundaries differ: some can deny an inbound turn, while Hermes Agent can screen the message and withdraw downstream tool authority on a block. The Codex CLI plugin can be installed, but runtime prompt interception was not certified in the recorded headless run. The repo does not ship a GitHub Copilot CLI integration. Check the matrix for the host version you use.

## How to read a result

| Result | Meaning |
| --- | --- |
| `PASS` | Inspection ran and found no covered compromise signal. |
| `FLAG` | Suspicious behavior was observed. |
| `BLOCK` | The configured policy rejects the input. |
| `DEGRADED` or `UNSCREENED` | Required behavioral inspection did not complete or did not run. |

Routing and coverage are separate. If the model is unavailable, a fail-open configuration may let a turn continue while reporting degraded coverage; that must not be mistaken for a behavioral pass. The canary is powerless at the application layer, not isolated by an operating-system sandbox. Little Canary is a sensing layer alongside tool policy and other controls, not a promise to catch every attack.

[Security](SECURITY.md) · [Host capability matrix](docs/host-capability-matrix.md) · [Benchmarks and methodology](benchmarks/README.md) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/hermes-labs-ai/little-canary/releases)

Apache-2.0. [Hermes Labs](https://hermes-labs.ai) builds agentic infrastructure for autonomous systems.
