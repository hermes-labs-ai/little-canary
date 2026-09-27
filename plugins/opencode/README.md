# Little Canary for OpenCode

Little Canary screens the text in a newly submitted OpenCode message through a
local service. A flagged prompt produces a warning and the turn continues.
OpenCode 1.18.32's `chat.message` hook has no typed input-rejection result, so
this package does not claim to block the turn.

## Set up

Requires Python 3.9+ and [Ollama](https://ollama.com/). Install Little Canary,
pull the model, and keep the screening service running while you use OpenCode:

```sh
pip install little-canary
ollama pull qwen2.5:1.5b
little-canary serve --mode advisory
```

Install the plugin package from npm after publication:

```sh
opencode plugin @hermes-labs-ai/little-canary-opencode@0.3.10
```

The package contains the OpenCode adapter, not the Python service or model
weights. It sends submitted message text to `http://127.0.0.1:18421/check` by
default. Set `LITTLE_CANARY_ENDPOINT` to another HTTP loopback `/check` URL if
needed.

## Scope

The adapter checks text parts of the current user message only. It does not
inspect prior conversation, attachments, files, tool arguments, or tool results.
The TUI shows a warning on flags and unavailable screening; CLI runs also
print it to stderr. A flag is a signal, not proof that the prompt is unsafe or
safe. See the
[host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md)
for the tested version and limits.
