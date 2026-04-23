# little-canary — Intent

A prompt injection detection layer for LLM apps and agents. Routes untrusted user input through a small, sandboxed sacrificial model before it reaches the main system, and returns a verdict (`block`, `flag`, or `pass`) with a risk score and per-layer trace. Designed to sit in front of an existing stack without replacing it. Intended for developers who can afford ~250ms of preflight latency and want inbound detection that goes beyond static regex rules.

## Accepts

- runs a two-layer check: structural filter first, canary probe second
- returns a `PipelineVerdict` with `safe`, `action`, `summary`, `canary_risk_score`, and per-layer `LayerResult` list
- blocks input when structural patterns match in `block` or `full` mode
- never blocks in `advisory` mode — returns a `SecurityAdvisory` with severity and signal list instead
- skips the canary probe when the structural filter fires and `skip_canary_if_structural_blocks` is True
- runs the structural filter against base64-decoded, hex-decoded, ROT13-decoded, and reversed variants of the input
- detects null bytes, Unicode homoglyphs, zero-width characters, and RTL override codepoints in layer 1
- accepts an optional `judge_model` to replace the regex `BehavioralAnalyzer` with an LLM classifier
- supports `provider="openai"` for any OpenAI-compatible API (OpenAI, MiniMax, Together, Groq, etc.)
- writes per-check audit records to `canary-audit.jsonl` and `canary-alerts.jsonl` when `audit_log_dir` is set
- stores input as SHA-256 hash in audit logs, never as raw text
- applies trust tiers (TRUSTED / KNOWN / UNKNOWN) when used via `CanaryGuard`
- rate-limits override grants to 5 per hour per caller via `CanaryGuard`
- fires `on_block`, `on_flag`, `on_pass` callbacks per verdict, caught and logged so they never crash the pipeline
- fails open when the canary model is unavailable — returns `safe=True` rather than dropping traffic
- exposes a persistent HTTP server (`little-canary serve`) with `POST /check` and `GET /health` endpoints
- reports canary model availability and current pipeline mode via `health_check()`

## Does not

- protect downstream tool calls or agent actions — only checks inbound user input
- guarantee detection of all prompt injection variants or function as a formal security control
- remove or sanitize the flagged input before returning it — `safe_input` is empty on block, unchanged otherwise
- store raw input text anywhere — audit logs hash-only
- execute or forward the canary's response — it is observed and discarded
- replace the production LLM or modify the application's generation logic
- require Ollama — also works with any OpenAI-compatible endpoint
- support concurrent requests from multiple threads without an external lock
