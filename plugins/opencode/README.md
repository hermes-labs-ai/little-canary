# Little Canary for OpenCode

Little Canary screens the text in a newly submitted OpenCode message and text
returned by tools through a local service. A flagged result produces a warning
and the turn continues. If the service rejects a tool result, the plugin
withholds that text before OpenCode sends it to the model. OpenCode 1.18.32's
`chat.message` hook has no typed input-rejection result, so the plugin cannot
block a submitted prompt.

## Set up

Requires Python 3.9+ and [Ollama](https://ollama.com/). Install Little Canary,
pull the model, and keep the screening service running while you use OpenCode:

```sh
pip install little-canary
ollama pull qwen2.5:1.5b
little-canary serve --mode advisory
```

Install the plugin package from npm:

```sh
opencode plugin @hermes-labs/little-canary-opencode@0.3.10
```

The package contains the OpenCode adapter, not the Python service or model
weights. It sends submitted message text and text tool results to
`http://127.0.0.1:18421/check` by default. Set `LITTLE_CANARY_ENDPOINT` to
another HTTP loopback `/check` URL if needed.

## Scope

The adapter checks text parts of the current user message, string tool output,
and text items or embedded `resource.text` in MCP tool results at
`tool.execute.after`. Rejected resource text is replaced while its URI is
preserved. It does not inspect prior conversation, attachments, tool arguments,
or non-text content such as images and binary resources. It screens
file text only when a tool returns it as text; it cannot undo a tool call. The
TUI shows warnings on flags and unavailable or degraded screening, retaining a
known flag alongside incomplete-coverage warnings; CLI runs also print them
to stderr.
Unavailable screening leaves the original text in place. The local server
rejects bodies over 64 KiB, so those results also pass through with a warning.
A flag is a signal, not proof that the text is unsafe or safe. See the
[host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md)
for the tested version and limits.
