# Worked examples

Four independently linkable examples. Each one has an **input**, an **output**, and **limits**, and each is derived from evidence already committed in this repository (a recorded capture, a public JailBench case, a host SDK declaration), not from invented text. No example uses a user's or private corpus.

Every output below is one of: **recorded** (captured earlier from a live model, replayed offline), **offline-executed** (produced by running the code with no model reachable), or **quoted** (copied from a committed file). None shows a fresh live-model verdict, and none is evidence of protection: Little Canary is advisory input-risk sensing, not a security guarantee.

| Example | Evidence kind | Shows |
|---|---|---|
| [01 Recorded canary compromise](01-recorded-canary-compromise.md) | recorded live capture, replayed | a compromised canary response becoming `BLOCK`, next to a clean `PASS` |
| [02 JailBench sandwich pair](02-jailbench-sandwich-pair.md) | public case, offline-executed | the structural layer blocking an injection and also its benign control |
| [03 Batch coverage hold](03-batch-coverage-hold.md) | offline-executed, **unreleased** | `degraded` and exit `2` when the canary model is unreachable |
| [04 Copilot cannot refuse a prompt](04-copilot-cannot-refuse.md) | quoted upstream SDK types | why the same screening cannot stop a prompt on one host |

The facts quoted here are pinned to their sources by `tests/test_public_examples.py`.
