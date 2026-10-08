# Ingest eval corpus (local, illustrative)

`corpus.jsonl` is a small, hand-authored corpus for exercising the experimental
`little-canary ingest` surface end to end. It is meant for local development and
regression work, not for publishing numbers.

## Claim boundary

- Scores produced from this corpus are **local and illustrative**. They make no
  detection-rate, false-positive-rate, or latency claim, and they must not be
  presented as one. The corpus is small, author-written, and not drawn from a
  real-world distribution. See `benchmarks/README.md` for what a future numeric
  claim would require.
- The `benign` / `injected` labels are **assigned by the corpus author**. They
  are not external gold labels and have not been independently adjudicated.
- An admitted record means the record completed the configured checks and
  satisfied policy. It is not a statement that the content is harmless.

## Record shape

One JSON object per line:

```json
{"id": "inj-meta-title-01", "source": "docs/committee", "text": "...",
 "metadata": {"title": "...", "author": "..."},
 "expect": {"label": "injected", "vector": "metadata", "note": "...", "payload": "..."}}
```

- `id`, `source`, `text` and optional `metadata` (string keys to string values)
  are the ingest record.
- `expect` is **eval-only**:
  - `label`: `benign` or `injected`.
  - `vector`: where the injected payload sits, or why the record is special.
  - `note`: a short human description. For most injected records it also says
    whether the corpus author expects the payload to be *structurally obvious*
    (the regex structural filter matches it) or *structurally quiet* (only the
    canary layer could observe it); some notes, such as the one on
    `inj-meta-title-01`, say neither.
  - `payload` (injected records only): the exact injected substring. It lets the
    structural test prove where the payload sits; it is not an input to ingest.

### The runner must strip `expect`

The ingest reader accepts only the top-level keys `id`, `source`, `text` and
`metadata`; any other key makes the record malformed, so that nothing unscreened
can ride through to export. A record passed to `ingest_records()` with `expect` still
attached would be held as `malformed` and never checked. The eval runner removes
`expect` from each record before ingesting and keeps the labels on the side,
joined back by record index (the record's position in the ingested list).

## Vectors

| vector | label | meaning |
|---|---|---|
| `none` | benign | no injected payload |
| `over_budget` | benign | needs more than `max_segments` (8) segments at 3500/500; expected held as `over_budget` with nothing checked. This is an operational hold, not a detector result |
| `text_start` | injected | payload in the first 10% of a single-segment text |
| `text_middle` | injected | payload between 20% and 80% of a single-segment text |
| `text_end` | injected | payload in the last 10% of a single-segment text |
| `metadata` | injected | text is a benign base copied verbatim; the payload is in a metadata value (title, author, subject, filename) |
| `long_text` | injected | ~9000-char document (3 text segments); payload sits only in the last segment, so scanning only the first segments would miss it |

Injected payloads are written for this corpus and cover the attack families in
`benchmarks/prompts.json`: instruction override, role/persona hijack,
system-prompt exfiltration, tool/action requests, encoded (base64, hex) payloads,
hidden markdown/HTML-comment instructions, non-English overrides, and
"assistant, do X" lines addressed to the reading agent.

## Known traps (benign records a detector may hold)

- `benign-security-writeup-01` and `benign-security-writeup-02` quote attack
  phrases as specimens (for example "ignore previous instructions"). The
  structural filter matches the quoted phrase; a hold here is a detector false
  positive on quoting, not an injection.
- `benign-runbook-01` contains a `sudo` command, which the structural filter's
  shell-command pattern matches.

## Things to know when scoring

- Ingest screens a record's `id` and `source` together with its metadata, so the
  descriptive corpus ids (`benign-...`, `inj-...`) would show the label to the
  canary. The runner prevents this: before ingest it replaces every `id` with a
  neutral `doc-NNNN` and every `source` with `corpus`, and after the run it
  restores the original ids by record index for scoring. The descriptive ids
  never reach the canary through the runner.
- Every record carries `id` and `source`, so every record has at least one
  metadata segment in addition to its text segments.
- Ingest reports a plaintext `id` only for admitted records; a held record
  carries only `id_sha256`. The runner therefore never joins results to labels
  by `id`; it joins by index and cross-checks each result's `id` or `id_sha256`
  against the neutral id at that index.
- `benign-long-01` and `inj-long-01` share the same base document; they differ
  only by the payload inserted near the end.
- A held record whose reasons are only operational or coverage reasons
  (`over_budget`, `degraded`, `unexercised`, `error`, `incomplete`, `malformed`)
  is not a detector miss and not a detector false positive.

## Validation

`tests/test_ingest_eval_corpus.py` checks the corpus structure offline: shape,
unique ids, allowed labels and vectors, minimum counts, segment arithmetic for
the long and over-budget records, payload positions, and that metadata-vector
records carry benign text. Do not change the corpus while comparing versions
without recording the old and new SHA-256 of `corpus.jsonl`.

## Running

`run_eval.py` ingests the corpus and scores each record as `true_hold`, `miss`
(detector miss), `false_hold` (detector false positive), `coverage_hold`
(operational/coverage hold, not a detector error) or `admitted_benign`. Output
is local and illustrative for this corpus, this run; it is not a benchmark.

Before ingesting, the runner strips `expect` and replaces every `id` with a
neutral `doc-NNNN` (corpus line order) and every `source` with `corpus`, so the
label never reaches the canary through the metadata segment. Labels are restored
by record index after the run. The mapping back to the original ids is in the
`--json` document; a `--manifest` carries neutral ids only (plaintext for
admitted records, `id_sha256` only for held ones).

For a live run the runner builds the Ollama canary with a context window
(`canary_num_ctx`) large enough to hold a whole segment under the policy; ingest
refuses to run with an unset or smaller window, because the backend would
otherwise silently truncate long segments. Ingest also refuses to run when
Ollama's `/api/show` does not report a trained context length at least that
large for the canary model, including when the backend is unreachable. The
value used is recorded as
`canary_num_ctx` in the `--json` header (`null` for the offline fake, which has
no canary). The offline fake runs with `ingest_records(..., unverified_pipeline=True)`,
so its manifest records `pipeline.canary_context_verified: false` and `verify_export`
refuses it.

```sh
# scorer self-test, no model (deterministic stand-in; NOT a detector result)
python benchmarks/ingest_eval/run_eval.py --offline-fake
# live subset with a manifest (slow on CPU)
python benchmarks/ingest_eval/run_eval.py --ids benign-security-writeup-01,inj-meta-title-01 \
  --canary-model qwen2.5:1.5b --timeout 600 --manifest /tmp/ingest-eval-manifest.json --json
```
