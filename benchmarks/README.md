# Benchmarks

This directory holds Little Canary's benchmark runners and result files.

There are two kinds of benchmark here:

1. **Internal red-team suite** — hand-crafted prompts shipped in this repo
   (`prompts.json`, `prompts_fp_realistic.json`). Fully self-contained: run
   `red_team_runner.py` / `run_fp_test.py` and you reproduce it end to end.
2. **External TensorTrust suite** — 400 human-written prompt-injection attacks
   from the TensorTrust dataset (Toyer et al. 2023). The dataset itself is
   **not committed here** — it is third-party data (CC-BY) and we do not
   redistribute it. The runner scripts and our result files *are* committed, so
   the result is reproducible once you fetch the dataset yourself.

The rest of this file documents the TensorTrust suite.

## Result: TensorTrust 400

Full Little Canary pipeline (structural filter + `qwen2.5:1.5b` canary probe +
a production model), judged by `claude-haiku-4-5`, over 400 TensorTrust attacks
(`n = 400`):

| Production model behind the canary | Detection | Caught  | Missed | Model alone (no canary) |
|------------------------------------|-----------|---------|--------|-------------------------|
| claude-opus-4-6                    | **99.0%** | 396/400 | 4      | 97.5%                   |
| qwen3:4b                           | 96.8%     | 387/400 | 13     | 91.8%                   |
| llama3.1:8b                        | 94.5%     | 378/400 | 22     | 86.2%                   |
| dolphin3:8b                        | 94.2%     | 377/400 | 23     | 85.5%                   |
| llama3.2:3b (`llama3.2:latest`)    | **94.8%** | 379/400 | 21     | 86.8%                   |
| mistral:7b                         | 93.5%     | 374/400 | 26     | 83.6%                   |
| gemma3:12b                         | 92.2%     | 369/400 | 31     | 80.5%                   |

The structural filter alone blocked 241/400 attacks before any production-model
call. The "model alone" column is each model's own refusal rate on the same 400
attacks with no canary in front (the raw baselines below).

The headline pairing — **99.0% (Opus) / 94.8% (llama3.2:3b)** — is the high and
low ends of the table. All numbers above come from
`results_external_attacks/model_comparison/comparison_summary.json` (and the
per-model `results_*.json` next to it).

### False positives

**0 / 40** false positives on `prompts_fp_realistic.json` — 40 realistic chatbot
prompts (the same figure reported in the main README's Benchmark Results table).
This benign set is committed and runs with `run_fp_test.py`, so the
false-positive number is reproducible directly from this repo:

```bash
ollama pull qwen2.5:1.5b
python3 run_fp_test.py
```

## What is committed vs what you fetch

**Committed (Little Canary's own outputs and scripts):**

- runner scripts: `multi_model_benchmark.py`, `raw_baseline_benchmark.py`,
  `build_external_datasets.py`
- pipeline results: `results_external_attacks/model_comparison/` —
  `comparison_summary.json` plus one `results_<model>.json` per model, and the
  combined `benchmark_log.txt`
- raw model-alone baselines:
  `results_external_attacks/baseline_<model>_tensortrust-sample-400.json`
- the opus raw-baseline run log:
  `results_external_attacks/raw_baseline_opus_tensortrust.log`

**Not committed (you fetch it):**

- the TensorTrust attack prompts themselves (third-party CC-BY data).

## Reproduce it

You need: the TensorTrust dataset, Ollama with `qwen2.5:1.5b` pulled, and an
`ANTHROPIC_API_KEY` (for an API production model and for the Haiku judge).

```bash
# 1. Fetch the TensorTrust dataset (CC-BY) from its public release.
#    Project + data:  https://tensortrust.ai
#    Code/data repo:  https://github.com/HumanCompatibleAI/tensor-trust
#    Save a 400-attack sample as: benchmarks/tensortrust-sample-400.json
#    Expected shape: a JSON list of attack objects (or {"attacks": [...]}),
#    each with a "text" field holding the attack prompt. See the loader in
#    multi_model_benchmark.py for the exact shapes accepted.

# 2. Pull the canary model.
ollama pull qwen2.5:1.5b

# 3. Run the full pipeline benchmark (this produces the 99.0% Opus number).
export ANTHROPIC_API_KEY=sk-...
python3 multi_model_benchmark.py \
    --attacks-file tensortrust-sample-400.json \
    --models claude-opus-4-6

# 4. (optional) Raw model-alone baseline, no canary in front:
python3 raw_baseline_benchmark.py \
    --model claude-opus-4-6 \
    --attacks-file tensortrust-sample-400.json
```

Results are written under `results_external_attacks/`. Compare your
`detection_rate` against
`results_external_attacks/model_comparison/comparison_summary.json`.

`build_external_datasets.py` builds a *separate* combined set (Garak + Gandalf +
deepset, all Apache-2.0 / MIT) into `external_attacks.json`. It does **not**
build the TensorTrust sample — use it only if you also want to benchmark on
those open sets.

## Attribution

The 400 attacks come from the TensorTrust dataset:

> Sam Toyer, Olivia Watkins, Ethan Adrian Mendes, Justin Svegliato, Luke Bailey,
> Tiffany Wang, Isaac Ong, Karim Elmaaroufi, Pieter Abbeel, Trevor Darrell, Alan
> Ritter, Stuart Russell. *Tensor Trust: Interpretable Prompt Injection Attacks
> from an Online Game.* 2023. arXiv:2311.01011.

The TensorTrust dataset is released under CC-BY. We do not redistribute it;
fetch it from the source above. Every result file in this directory is Little
Canary's own measurement over that data.
