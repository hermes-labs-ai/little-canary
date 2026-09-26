# Benchmarks and evaluation evidence

This directory contains historical runners, prompt corpora, and partial result artifacts. It is useful for regression work; it is not a current performance certificate for Little Canary `0.3.3`.

## Current claim boundary

This `0.3.3` evaluation guide makes no aggregate detection, false-positive,
latency, token-savings, or universal-repeatability claim. In particular, the
old `0/40` false-positive headline is not admitted by this guide because a
later live rerun did not reproduce it.

Historical TensorTrust tables and JSON files remain in the repository for inspection. They combine the structural filter, canary, and downstream production-model behavior; they must not be described as standalone canary accuracy. The third-party input sample is not committed, and the repository does not contain every per-model artifact previously claimed by this README. The historical “model alone” column is not admitted as a current baseline.

## Committed corpora

| File | Contents | `0.3.3` use |
|---|---|---|
| `prompts.json` | 160 attacks plus 20 safe/mixed cases | Deterministic structural decision vector and bounded adversarial case selection |
| `prompts_fp_realistic.json` | 40 benign hard negatives | Case-by-case false-positive investigation; no rate claim without a fresh preregistered run |

Do not change a corpus while comparing versions without recording old/new hashes and running both versions on both corpus revisions.

## Bounded `0.3.3` evaluation

The `0.3.3` capability/hardening change does not alter structural rules, analyzer patterns, weights, thresholds, or the default model. Its required evidence is therefore:

1. an exact base-to-head structural decision vector over all committed cases;
2. response-swapped controls showing that the behavioral verdict follows model residue rather than the known input;
3. a dedicated live clean/attack pair repeated five times for one exact runtime/model digest/configuration;
4. case-by-case live controls covering c1-03/c1-04/c1-05 variants, fp-c09/fp-c12/fp-c18/fp-c19, camouflage twins, and representative Unicode/multilingual text;
5. every degraded, error, transition, or classification flip reported and rerun twice.

These checks support only the observed cases. They do not establish a public rate.

## Requirements for a future numeric claim

Before publishing a percentage, freeze a separate evaluation boundary and record:

- exact source/artifact SHA-256 values;
- corpus source, revision, license, case IDs/order, and hashes;
- backend origin class, runtime version, model tag and immutable digest;
- system-prompt hash, temperature, seed, token/timeout settings;
- per-case structural, behavioral, downstream, degraded, and error states;
- TP, FP, TN, FN, denominators, confidence intervals, and run-to-run flips;
- a structural-only baseline and response-swapped causality controls;
- complete redistributable result files or an explicit licensing/privacy limitation.

Never drop degraded or skipped cases from a denominator without displaying both the full and completed-only populations.

## Running historical tools

The scripts can still support local research, but they may call Ollama or remote APIs and write result files. Inspect their arguments and egress before use. Never run them against a shared model service or with production prompts/credentials merely to reproduce a headline.

The historical external dataset is TensorTrust (Toyer et al., 2023, arXiv:2311.01011), distributed separately under CC-BY. Little Canary does not redistribute that dataset.

## Reproducible local model comparison

`red_team_runner.py` uses the two committed corpora above. An IDs file is a JSON list of unique case IDs, in the intended run order; IDs can come from either corpus. Keep the same file, source revision, threshold, Ollama configuration, and host for every model in a comparison. Use `--corpus all` to run all 220 committed cases without an IDs file. The default corpus remains `prompts.json` for the dashboard.

```sh
python3 benchmarks/red_team_runner.py --mode pipeline --model qwen2.5:1.5b --ids-file screening-ids.json --timeout 30 --warmup --headless --output /tmp/canary-pipeline.jsonl
python3 benchmarks/red_team_runner.py --mode model-only --model qwen2.5:1.5b --ids-file screening-ids.json --timeout 30 --warmup --headless --output /tmp/canary-model-only.jsonl
python3 benchmarks/red_team_runner.py --mode structural-only --ids-file screening-ids.json --headless --output /tmp/canary-structural-only.jsonl
python3 benchmarks/run_fp_test.py --mode model-only --model qwen2.5:1.5b --headless --output /tmp/canary-benign.jsonl
```

`pipeline` exercises both layers on every case, including cases the structural filter blocks. `model-only` disables the structural filter, so its model results are independent of filtered traffic. `structural-only` disables the canary. All three use block mode and the same committed prompts. The canary probe sends `think: false` to Ollama; the output header records its model tag, prompt hash, temperature, seed, token limit, timeout, and warmup choice. Record the immutable model digest and Ollama/runtime version separately with the results. The warmup request is not scored.

Headless output is JSONL: one run header, one result per case flushed immediately, then a completion summary. A missing completion line indicates an interrupted run. Case records include both layer block outcomes, degraded and analysis status, total wall latency, structural layer latency, and canary layer latency (probe plus analysis). `coverage_reason` records a bounded cause when known, such as `output_limit`, `timeout`, `unavailable`, or `analysis_failed`; it does not change routing or scoring. Incomplete or failed coverage has `scored: false`, `actual_safe: null`, and `correct: null`; its `raw_actual_safe` records the pipeline's routing outcome without treating fail-open as a successful benign pass or an attack miss. Adjudicated rates use only scored cases. The summary also reports attack and benign total/scored/unscored counts and a conservative `attack_detection_full_population_rate` (scored blocks divided by all attack cases). Latency summaries distinguish all attempted cases from scored cases, so fast failures do not masquerade as a model speedup. A model unavailable at startup exits nonzero. The live dashboard remains available by omitting `--headless --output`.
