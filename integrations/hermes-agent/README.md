# Little Canary for Hermes Agent

Install this native plugin directory with `hermes plugins install hermes-labs-ai/little-canary/integrations/hermes-agent`. The directory bundles the Little Canary runtime and declares its `requests` dependency. Its contents mirror the package source in the repository root; the integration test checks that they stay in sync.

The `pre_llm_call` hook screens each user turn and can add a bounded warning. It cannot prevent the prompt from reaching the model. A genuine BLOCK verdict makes `pre_tool_call` refuse downstream tools for that turn. If screening is unavailable, the plugin leaves tools available and reports degraded coverage.

See the [main documentation](https://github.com/hermes-labs-ai/little-canary#hermes-agent) for setup and limits.
