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
  - `note`: a short human description; for injected records it says whether the
    payload is *structurally obvious* (the regex structural filter matches it) or
    *structurally quiet* (only the canary layer could observe it).
  - `payload` (injected records only): the exact injected substring. It lets the
    structural test prove where the payload sits; it is not an input to ingest.

### The runner must strip `expect`

The ingest reader treats unknown top-level keys as malformed (SPEC §3,
`unknown_keys`), so that nothing unscreened can ride through to export. A
record passed to `ingest()` with `expect` still attached would be held as
`malformed` and never checked. The eval runner must remove `expect` from each
record before ingesting and keep the labels on the side, joined back by `id`.

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

- `id` and `source` are part of the screened metadata material (SPEC §3). The
  descriptive ids (`benign-...`, `inj-...`) therefore reach the canary. Keep this
  in mind when reading results; it is a known limitation of this corpus.
- Every record carries `id` and `source`, so every record has at least one
  metadata segment in addition to its text segments.
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
