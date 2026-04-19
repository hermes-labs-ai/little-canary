# AGENTS.md

Little Canary is a prompt-injection detection library that uses a sacrificial canary model as an inbound risk sensor.

## Use it for

- screening untrusted text before it reaches a main model or agent
- combining structural pattern checks with behavioral compromise checks
- returning `block`, `flag`, or `pass` decisions plus advisory text

## Do not use it for

- formal security guarantees
- audited benchmark comparisons
- replacing runtime containment or outbound tool controls

## Minimal commands

```bash
pip install -e ".[dev]"
little-canary serve --help
pytest -q
ruff check little_canary tests
mypy little_canary
```

## Output shape

- Python API returns a verdict object with safety, action, summary, and advisory fields
- CLI currently exposes the local HTTP server entry point: `little-canary serve`
- benchmark scripts live under `benchmarks/` and are not part of the default CLI flow

## Success means

- the pipeline can evaluate text and produce a deterministic verdict for mocked tests
- structural and behavioral layers agree with the documented modes
- the repo remains usable with local Ollama or OpenAI-compatible backends

## Common failure cases

- the canary backend is unavailable and the repo passes through by design
- users expect this tool to replace broader agent runtime controls
- benchmark claims are quoted without the methodology caveats in the README

## Maintainer notes

- preserve fail-open behavior unless there is an explicit versioned policy change
- keep benchmark caveats aligned with README claims
- keep tests offline and mock network calls
