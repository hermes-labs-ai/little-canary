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
