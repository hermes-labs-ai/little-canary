# Little Canary for OpenCode

Little Canary screens the text in a newly submitted OpenCode message and text
returned by tools through a local service. A flagged result produces a warning
and the turn continues. If the service rejects a tool result, the plugin
withholds that text before OpenCode sends it to the model. OpenCode 1.18.32's
`chat.message` hook has no typed input-rejection result, so the plugin cannot
block a submitted prompt.

## Set up

Requires OpenCode (tested contract: 1.18.32), Git, Python 3.9+, and
[Ollama](https://ollama.com/). Install Little Canary,
pull the model, and keep the screening service running while you use OpenCode:

```sh
pip install little-canary
ollama pull qwen2.5:1.5b
little-canary serve --mode advisory
```

Advisory mode warns and forwards detected tool text. To enable tool-result
withholding, stop that service and run the blocking configuration instead:

```sh
little-canary serve --mode block
```

Block mode lets the plugin replace tool text when the service returns
`safe: false`. It still cannot block a submitted prompt or undo a tool call.

The OpenCode npm package is not published. Install the reviewed source revision
below from the project directory where you use OpenCode:

```sh
git clone https://github.com/hermes-labs-ai/little-canary.git little-canary-source
git -C little-canary-source checkout f92a15fdebb46c41870a8903496075329750efab
opencode plugin "$(pwd)/little-canary-source/plugins/opencode"
```

Keep that checkout in place: OpenCode registers the local package directory.
Its [1.18.32 path resolver](https://github.com/anomalyco/opencode/blob/545f51d26cc39a907d2867492d498d9607ea5fa4/packages/opencode/src/plugin/shared.ts#L171-L191)
supports this absolute-directory form, and the package's `main` identifies its
server entry. Offline tests load both the local directory and packed archive;
this source route is not an npm release or a new installed-host certification.

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
