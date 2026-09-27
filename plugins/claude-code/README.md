# Little Canary for Claude Code

Little Canary screens the submitted prompt before a Claude Code turn starts. It
sends the current prompt to a separately running Little Canary service on your
machine. The service uses a tool-free canary model and structural checks to
return a verdict. When the service explicitly rejects the prompt, this
`UserPromptSubmit` hook blocks the turn. This is the Claude Code adapter for
the [open-source Little Canary project](https://github.com/hermes-labs-ai/little-canary);
the repository README explains the detector and its [known limits](https://github.com/hermes-labs-ai/little-canary#what-little-canary-is-and-isnt).

## Set up

Install Python 3.9+ and [Ollama](https://ollama.com/), then start the local
service in block mode:

```sh
python3 -m pip install little-canary==0.3.10
ollama pull qwen2.5:1.5b
little-canary serve --mode block --canary-model qwen2.5:1.5b
```

In Claude Code, install the plugin from the Hermes Labs marketplace:

```sh
claude plugin marketplace add hermes-labs-ai/little-canary
claude plugin install little-canary@hermes-labs
```

The plugin contains the hook adapter, not the Python service or model weights.
It uses `http://127.0.0.1:18421/check` by default. You can set
`LITTLE_CANARY_ENDPOINT` to another HTTP loopback `/check` URL and
`LITTLE_CANARY_TIMEOUT_MS` to 100–5000 milliseconds.

## Coverage and data handling

The adapter sends only the current submitted prompt to the configured loopback
service. It does not inspect earlier conversation, files Claude reads, tool
arguments, or tool results. It does not log prompt text or send it to a remote
service. The service's configured canary backend determines where model
processing happens; the default Ollama endpoint is local.

A `BLOCK` can reject benign quoted attack text. If screening fails or reports
degraded coverage, the default policy lets Claude Code continue with a visible
warning. Set `LITTLE_CANARY_FAILURE_MODE=deny` for a fail-closed hook policy.
Neither mode proves that allowed input is safe. Use tool permissions and
sandboxing as separate controls. This hook runs in Claude Code; it does not
screen Claude chat or Cowork. See the [host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md)
for observed host versions and boundaries.
