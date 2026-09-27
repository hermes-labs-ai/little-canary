# Little Canary for Pi

Little Canary screens submitted Pi input through a local service before Pi
starts the agent turn. In advisory mode, a flagged prompt continues with a
warning. If the service returns an unsafe verdict under a blocking policy, the
extension handles the input before Pi sends it to a model.

## Set up

Requires Python 3.9+ and [Ollama](https://ollama.com/). Install Little Canary,
pull the model, and keep the screening service running while you use Pi:

```sh
pip install little-canary
ollama pull qwen2.5:1.5b
little-canary serve --mode advisory
```

Install the Pi package:

```sh
pi install npm:@hermes-labs-ai/little-canary-pi@0.3.10
```

The extension sends the current input to `http://127.0.0.1:18421/check`. Set
`LITTLE_CANARY_ENDPOINT` to another HTTP loopback `/check` URL if needed. The
package does not include the Python service or model weights.

## Scope

The extension uses Pi's `input` event. It checks submitted text, including Pi's
interactive, RPC, and extension-sourced input, before agent processing. It does
not inspect earlier conversation, files, or tool results. If screening is
unavailable, Pi continues with a warning. A flag is a signal, not proof that
the prompt is unsafe or safe. See the [host capability matrix](https://github.com/hermes-labs-ai/little-canary/blob/main/docs/host-capability-matrix.md)
for tested Pi versions and boundaries.
