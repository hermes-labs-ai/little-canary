# Little Canary for OpenClaw

This native OpenClaw plugin screens the current prompt at `before_agent_run`,
after OpenClaw builds the prompt and before supported embedded or CLI runners
submit it to a model. It sends that prompt to a separately running Little
Canary 0.3.10 service on loopback. An explicit unsafe verdict blocks the run.

## Install

Use OpenClaw 2026.9.5 or 2026.9.6 on a supported Node runtime. Install and
start the Python service first:

```sh
python3 -m pip install little-canary==0.3.10
ollama pull qwen2.5:1.5b
little-canary serve --mode block --canary-model qwen2.5:1.5b
```

Then install the OpenClaw package and grant the conversation hook access it
needs:

```sh
openclaw plugins install clawhub:@hermes-labs-ai/little-canary-openclaw
openclaw plugins enable little-canary-openclaw
openclaw config set plugins.entries.little-canary-openclaw.hooks.allowConversationAccess true
openclaw plugins inspect little-canary-openclaw --runtime
```

Review the conversation-access grant before enabling it. The package includes
only the OpenClaw adapter; it does not install or start the Python service.
For a source checkout, use `openclaw plugins install ./plugins/openclaw`
instead of the ClawHub locator.

## Boundary and failure behavior

Only the current `event.prompt` is screened. This plugin does not inspect
session history, tool results, or later text the agent reads. An explicit
`safe: false` service verdict blocks the run before model submission. A
service error, malformed response, or degraded coverage allows the run and
logs a warning. The plugin does not expose a fail-closed setting. OpenClaw's
isolated `agent exec` path bypassed this hook in the tested 2026.9.5 host and
is outside the claimed coverage.

The adapter accepts only an `http://127.0.0.1:<port>` service URL (default:
`http://127.0.0.1:18421`) and rejects redirects. It sends the prompt to that
loopback service and does not log prompt text. The service's configured canary
backend determines whether processing remains on the same machine; the
default Ollama URL is loopback. This is a sensing layer, not a security
guarantee or a replacement for tool policy and sandboxing.

Source, tests, and the host capability matrix live in the
[Little Canary repository](https://github.com/hermes-labs-ai/little-canary).
