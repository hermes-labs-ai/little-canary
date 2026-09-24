# Little Canary for Hermes Agent

Little Canary screens Hermes Agent user turns with structural checks and a local
powerless canary model. A BLOCK verdict withdraws downstream tool access for
that turn. The original prompt still reaches Hermes's model.

With Hermes Agent 0.21.3 or later, local Ollama, and `qwen2.5:1.5b`:

```bash
ollama pull qwen2.5:1.5b
hermes plugins install little-canary
hermes plugins enable little-canary
hermes plugins list
```

The catalog entry installs this directory at a reviewed commit. The directory
bundles Little Canary's runtime and compatible `requests` dependency. It runs
inside Hermes; it does not require the separate `little-canary serve` adapter.

For a direct install before the catalog entry reaches your client:

```bash
hermes plugins install hermes-labs-ai/little-canary/integrations/hermes-agent --no-enable
hermes plugins enable little-canary
```

The `pre_llm_call` hook screens the current user message once and can add a
bounded warning. It cannot prevent the prompt from reaching the model. On a
genuine BLOCK, `pre_tool_call` refuses downstream tools for that turn. If
screening is unavailable, the plugin leaves tools available and reports
degraded coverage. `on_session_end` clears the session's stored decisions.

For setup, verification and behavior, read the
[Little Canary Hermes Agent guide](https://littlecanary.ai/docs/integrations/hermes-agent).
