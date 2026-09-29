# CLAUDE.md — Agent Context for Little Canary

Priority order: preserve security and coverage semantics; preserve public API behavior;
then minimize the diff. Treat each user request as an independent task and carry prior
task state forward only when the user explicitly asks.

## Project Overview

Little Canary is a prompt injection detection library that uses a small, sacrificial LLM as a behavioral probe. Instead of classifying inputs, it feeds user input to a sandboxed canary model and analyzes the canary's response for signs of compromise. Three deployment modes: block, advisory, full. Runs locally via Ollama.

## Tech Stack

- **Language:** Python 3.9+ (tested on 3.9–3.13)
- **Dependencies:** `requests` (only runtime dependency)
- **Optional:** `anthropic` (benchmarks only), `pytest` (dev)
- **LLM Runtime:** Ollama (local inference, any model)
- **Package Manager:** pip via `pyproject.toml`
- **Build System:** setuptools

## Directory Layout

```
little_canary/                    # Core library (this is the installable package)
  __init__.py                  # Public API exports, version
  structural_filter.py         # Layer 1: regex patterns + decode-then-recheck
  canary.py                    # Layer 2: sends input to sacrificial LLM via Ollama
  analyzer.py                  # Regex-based behavioral analysis (two strategies)
  judge.py                     # LLM judge (experimental, replaces analyzer)
  pipeline.py                  # Orchestrator: wires layers together, mode logic

examples/                      # Integration examples (not part of package)
  generic_example.py           # Minimal usage
  chatbot_example.py           # Customer chatbot (block mode)
  clawdbot_example.py          # Email agent (full mode with quarantine)

benchmarks/                    # Test harnesses (not part of package)
  prompts.json                 # 160 adversarial + 20 safe test prompts (180 total)
  prompts_fp_realistic.json    # 40 realistic false positive prompts
  red_team_runner.py           # Live dashboard + SSE event stream
  run_fp_test.py               # False positive test (terminal)
  full_pipeline_test.py        # End-to-end with production LLM
  dashboard.html               # Browser UI for red_team_runner
```

## Development Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run false positive test (requires Ollama + qwen2.5:1.5b)
cd benchmarks && python3 run_fp_test.py

# Run red team dashboard
cd benchmarks && python3 red_team_runner.py --canary qwen2.5:1.5b

# Run full pipeline test
cd benchmarks && python3 full_pipeline_test.py --canary qwen2.5:1.5b --production gemma3:27b
```

## Architecture Decisions

### Pipeline Flow
1. `SecurityPipeline.check(user_input)` is the single entry point
2. Layer 1 (structural filter) runs first — pure regex, ~1ms
3. If structural filter blocks and `skip_canary_if_structural_blocks=True` (default), returns immediately
4. Layer 2 (canary probe) sends input to Ollama, gets response
5. Analysis layer (BehavioralAnalyzer or LLMJudge) classifies canary response
6. Mode logic determines final verdict (block, advisory, or pass)

### Mode Logic (in pipeline.py)
- **block:** Any `should_block` from analyzer -> blocked
- **advisory:** Never blocks. All signals become `SecurityAdvisory` objects
- **full:** `hard_blocked` signals -> blocked. Non-hard signals -> advisory

The `hard_blocked` flag is set when signals match `HARD_BLOCK_CATEGORIES` in `analyzer.py`.

### Analyzer vs Judge
Both implement the same duck-typed interface: `analyze(CanaryResult) -> AnalysisResult`. The pipeline stores whichever is configured in `self.analyzer`. There is no formal Protocol/ABC — it's implicit duck typing.

`judge.py` defines its own `Signal` and `AnalysisResult` dataclasses that mirror those in `analyzer.py`. This is intentional duplication to keep the judge module self-contained.

### Fail-Open Design
All error paths (Ollama down, timeout, HTTP error, parse failure) return `should_block=False`. This is deliberate: availability over security. The `health_check()` method exists to verify Ollama connectivity at startup.

## Code Conventions

- Dataclasses for all data structures (no Pydantic)
- `logging.getLogger(__name__)` in every module
- Type hints on all public method signatures
- Private methods prefixed with `_`
- Detection patterns are tuples of `(regex_pattern, description_string)`
- Temperature=0 and seed=42 for deterministic canary output

## Key Constraints

- **Do not add dependencies** beyond `requests` to the core package
- **Do not modify benchmark prompt files** (`prompts.json`, `prompts_fp_realistic.json`) without re-running benchmarks
- **Ollama API format** is hardcoded — the `/api/chat` endpoint with `options` dict. No abstraction layer exists yet
- **Python 3.9 compatibility** is required (no `match` statements, no runtime `X | Y` union types)
- The `PipelineVerdict.to_dict()` method intentionally omits the raw `input` field for security

## Common Tasks

### Adding a new structural filter pattern
Edit `structural_filter.py` -> `_build_patterns()`. Add a tuple `(regex_string, reason_string)` to the `raw_patterns` list.

### Adding a new behavioral detection check
Edit `analyzer.py`. Either add patterns to an existing `_check_*` method, or create a new method and call it from `analyze()`.

### Adding a new deployment mode
Edit `pipeline.py`. Add the mode name to `VALID_MODES`. Add branching logic in the structural filter and canary probe sections of `check()`.

### Testing a change
Run `pytest` to run the unit test suite (157 tests, no Ollama required). Run `cd benchmarks && python3 run_fp_test.py` to verify false positive rate. Run `python3 red_team_runner.py --canary qwen2.5:1.5b` for full adversarial testing.

## Known Issues
- `LLMJudge` is marked experimental; binary SAFE/UNSAFE output means no risk scoring granularity
- The dashboard server (`red_team_runner.py`) uses a basic `HTTPServer` — not production-grade
