# AGENTS.md

Little Canary is a prompt-injection detection library that uses a sacrificial canary model as an inbound risk sensor.

## Use it for

- screening untrusted text before it reaches a main model or agent
- combining structural pattern checks with behavioral compromise checks
- returning `block`, `flag`, `pass`, or `degraded` state plus advisory text

## Do not use it for

- formal security guarantees
- audited benchmark comparisons
- replacing runtime containment or outbound tool controls

## Minimal commands

```bash
pip install -e ".[dev]"
little-canary --version
little-canary demo --replay  # exits 2 until an admitted fixture is packaged
little-canary demo --live --backend ollama --model qwen2.5:1.5b --endpoint http://127.0.0.1:11434
little-canary serve --help
pytest -q
ruff check little_canary tests
mypy little_canary
```

## Output shape

- Python API separates routing (`safe`) from coverage (`degraded`, `canary_status`, `analysis_method`, `analysis_status`)
- failed/unavailable coverage keeps risk unset and never means an exercised PASS
- CLI exposes explicit replay/live demo paths and the local HTTP server
- benchmark scripts live under `benchmarks/` and are not part of the default CLI flow

## Success means

- when an admitted fixture is packaged, replay reproduces analyzer behavior for those exact bytes without a network call
- a build without that fixture must report `REPLAY UNAVAILABLE`; this is a hold, not a safe result
- live evidence names its backend, model digest, configuration, and observed result
- structural and behavioral layers agree with the documented modes
- the Ollama path and OpenAI-compatible protocol adapter pass their declared
  offline tests; live support remains bound to endpoint-specific evidence

## Common failure cases

- the canary backend is unavailable and fail-open routing passes through with a visible degraded state
- users expect this tool to replace broader agent runtime controls
- benchmark claims are quoted without the methodology caveats in the README

## Maintainer notes

- preserve fail-open behavior unless there is an explicit versioned policy change
- never treat replay, mock, or static evidence as a current live-model result
- keep benchmark caveats aligned with README claims
- keep tests offline and mock network calls
