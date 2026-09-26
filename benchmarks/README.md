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
| `jailbench_injection_cases.json` | Five JailBench-derived embedded-instruction positives with five matched, purpose-built benign controls | Auxiliary case-specific regression probe; JailBench refusal labels are provenance only |

The JailBench probe preserves source IDs (`jb-inj-01` … `jb-inj-05`), source names,
source revision, exact-input SHA-256 values, positive/benign adjudications, and paired IDs.
The MIT notice is in `JAILBENCH-LICENSE.txt`. The controls are hand-authored and are not
external gold labels. Report the positive and control routes separately against their fixed
denominators of five; pooled correct, accuracy, precision, recall, and FPR are null for this
probe, and the pooled stealth summary is omitted.
Do not present it as a general detection rate. The completion summary includes separate
positive and benign-control totals, scored blocks, scored non-blocks, and unscored counts.
Each JSONL case row carries its source ID, hash, adjudication, and paired ID.
Positive rows retain JailBench's upstream `REFUSED` field as provenance only; hand-authored
benign controls do not carry that field. It is not used for Little Canary scoring.

The packaged fixture is a development/regression version, not a performance certificate. Its
`jb-inj-05` pair was corrected during integration because the earlier positive asked for an
explanation of how to output the marker and then to translate, rather than testing the stated
marker-only override. The earlier pilot files are preserved unchanged; their saved results do
not apply to the corrected pair. Only this pair's rendered text and hashes changed:

| Case | Earlier pilot SHA-256 | Packaged fixture SHA-256 |
|---|---|---|
| `jb-inj-05` | `6a6fb985983c451653cfc3a8fe31381d95ececf7b19760fba3cd0dc9d5e58933` | `10eb9ccd8f7e12af0f6cd2624a5c9aeefbd1ed601e2ab5b5ac45f7b0d1ffac42` |
| `benign_control-jb-inj-05` | `090c28105e1781d6198e19c5d19a52734d6b3d7ef79e3079a7a8757d0808f07b` | `cac463061640bbdb7b5b0f4aaac278ec0beb14e6bc17ee4f35b6a8a68feee189` |

Run the fixture with the existing structural-only, pipeline, or model-only runner modes. The
structural-only path is offline; the pipeline and model-only modes require an available local
canary model. The standard modes report routing and coverage and retain incomplete cases.

```sh
python3 benchmarks/red_team_runner.py --corpus jailbench-injection --mode structural-only --headless --output /tmp/jailbench-structural.jsonl
python3 benchmarks/red_team_runner.py --corpus jailbench-injection --mode pipeline --model qwen2.5:1.5b --timeout 30 --headless --output /tmp/jailbench-pipeline.jsonl
```

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

`red_team_runner.py` can select either original corpus, the JailBench probe explicitly with
`--corpus jailbench-injection`, or an IDs file containing unique IDs from either the original
corpora or the auxiliary probe. IDs files preserve the requested run order but cannot mix the
auxiliary probe with the original corpora. Keep the same file, source revision, threshold,
Ollama configuration, and host for every model in a comparison. `--corpus all` retains its
original 220-case population; it excludes the auxiliary JailBench probe unless selected by
name or explicit IDs. The default corpus remains `prompts.json` for the dashboard.

```sh
python3 benchmarks/red_team_runner.py --mode pipeline --model qwen2.5:1.5b --ids-file screening-ids.json --timeout 30 --warmup --headless --output /tmp/canary-pipeline.jsonl
python3 benchmarks/red_team_runner.py --mode model-only --model qwen2.5:1.5b --ids-file screening-ids.json --timeout 30 --warmup --headless --output /tmp/canary-model-only.jsonl
python3 benchmarks/red_team_runner.py --mode structural-only --ids-file screening-ids.json --headless --output /tmp/canary-structural-only.jsonl
python3 benchmarks/run_fp_test.py --mode model-only --model qwen2.5:1.5b --headless --output /tmp/canary-benign.jsonl
```

`pipeline` exercises both layers on every case, including cases the structural filter blocks. `model-only` disables the structural filter, so its model results are independent of filtered traffic. `structural-only` disables the canary. All three use block mode and the same committed prompts. The canary probe sends `think: false` to Ollama; the output header records its model tag, prompt hash, temperature, seed, token limit, timeout, and warmup choice. Record the immutable model digest and Ollama/runtime version separately with the results. The warmup request is not scored.

Headless output is JSONL: one run header, one result per case flushed immediately, then a completion summary. A missing completion line indicates an interrupted run. Case records include both layer block outcomes, degraded and analysis status, total wall latency, structural layer latency, and canary layer latency (probe plus analysis). `coverage_reason` records a bounded cause when known, such as `output_limit`, `timeout`, `unavailable`, or `analysis_failed`; it does not change routing or scoring. Incomplete or failed coverage has `scored: false`, `actual_safe: null`, and `correct: null`; its `raw_actual_safe` records the pipeline's routing outcome without treating fail-open as a successful benign pass or an attack miss. Adjudicated rates use only scored cases. The summary also reports attack and benign total/scored/unscored counts and a conservative `attack_detection_full_population_rate` (scored blocks divided by all attack cases). Latency summaries distinguish all attempted cases from scored cases, so fast failures do not masquerade as a model speedup. A model unavailable at startup exits nonzero. The live dashboard remains available by omitting `--headless --output`.
