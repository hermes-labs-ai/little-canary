# Little Canary for Hermes Agent

Install this native plugin directory with `hermes plugins install hermes-labs-ai/little-canary/integrations/hermes-agent`. The directory bundles the Little Canary runtime and declares its `requests` dependency. Its contents mirror the package source in the repository root; the integration test checks that they stay in sync.

Set `LITTLE_CANARY_MODEL` in the Hermes Agent process environment to an installed Ollama tag to select the sacrificial model, for example `LITTLE_CANARY_MODEL=gemma3:1b`. The default remains `qwen2.5:1.5b`. The model receives no tools; selecting a model does not grant it any host authority.

The `pre_llm_call` hook screens each user turn and can add a bounded warning. It cannot prevent the prompt from reaching the model. A genuine BLOCK verdict makes `pre_tool_call` refuse downstream tools for that turn. If screening is unavailable, the plugin leaves tools available and reports degraded coverage.

See the [main documentation](https://github.com/hermes-labs-ai/little-canary#hermes-agent) for setup and limits.
