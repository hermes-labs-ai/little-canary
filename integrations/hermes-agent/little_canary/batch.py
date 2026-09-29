"""
little_canary.batch — Batch pre-screening of documents/messages.

A thin loop over ``SecurityPipeline.check``: every item receives its own
independent verdict with the same coverage semantics as a single check. Nothing
here widens what Little Canary claims:

* no batch-level "safe" verdict exists — only per-item states and counts;
* an item whose check raises is reported as ``degraded``, never as ``pass``;
* item text is treated as data, is never echoed into the result, and is never
  granted instruction authority — results carry provenance (id, source, index,
  SHA-256, length) so callers can join verdicts back to their own records.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from .pipeline import PipelineVerdict, SecurityPipeline

logger = logging.getLogger("little_canary.batch")

SCHEMA = "little-canary-batch/v1"
DEFAULT_MAX_ITEMS = 1000

STATE_BLOCK = "block"
STATE_FLAG = "flag"
STATE_PASS = "pass"
STATE_DEGRADED = "degraded"
STATE_UNEXERCISED = "unexercised"
STATES = (STATE_BLOCK, STATE_FLAG, STATE_PASS, STATE_DEGRADED, STATE_UNEXERCISED)


def classify(verdict: PipelineVerdict) -> str:
    """Map a single verdict to one state, mirroring pipeline callback precedence."""
    if not verdict.safe:
        return STATE_BLOCK
    if verdict.degraded:
        return STATE_DEGRADED
    if verdict.advisory is not None and verdict.advisory.flagged:
        return STATE_FLAG
    if verdict.canary_status != "exercised":
        return STATE_UNEXERCISED
    return STATE_PASS


@dataclass
class BatchItem:
    """One untrusted text plus caller-supplied provenance labels."""

    text: str
    id: str | None = None
    source: str | None = None


@dataclass
class ItemResult:
    index: int
    id: str | None
    source: str | None
    sha256: str
    length: int
    state: str
    verdict: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "index": self.index,
            "id": self.id,
            "source": self.source,
            "sha256": self.sha256,
            "length": self.length,
            "state": self.state,
        }
        if self.verdict is not None:
            verdict = dict(self.verdict)
            verdict.pop("safe_input", None)  # never re-emit untrusted text
            out["verdict"] = verdict
        if self.error is not None:
            out["error"] = self.error
        return out


@dataclass
class BatchResult:
    items: list[ItemResult] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(STATES, 0)
        for item in self.items:
            counts[item.state] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "total": len(self.items),
            "counts": self.counts,
            "items": [item.to_dict() for item in self.items],
        }


def coerce_item(raw: Any, index: int = 0) -> BatchItem:
    """Accept a string, a ``BatchItem`` or a mapping with ``text``/``id``/``source``."""
    if isinstance(raw, BatchItem):
        item = raw
    elif isinstance(raw, str):
        item = BatchItem(text=raw)
    elif isinstance(raw, Mapping):
        item = BatchItem(text=raw.get("text"), id=raw.get("id"), source=raw.get("source"))  # type: ignore[arg-type]
    else:
        raise ValueError(f"item {index}: must be a string or object with 'text'")
    if not isinstance(item.text, str) or item.text == "":
        raise ValueError(f"item {index}: 'text' must be a non-empty string")
    for label in ("id", "source"):
        value = getattr(item, label)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"item {index}: '{label}' must be a string")
    return item


def screen_batch(
    pipeline: SecurityPipeline,
    items: Iterable[Any],
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> BatchResult:
    """Screen each item independently and return per-item results with provenance.

    Malformed items raise ``ValueError`` before any check runs; an oversized
    batch raises ``ValueError`` rather than being silently truncated.
    """
    prepared = [coerce_item(raw, i) for i, raw in enumerate(items)]
    if len(prepared) > max_items:
        raise ValueError(f"batch has {len(prepared)} items; limit is {max_items}")

    result = BatchResult()
    for index, item in enumerate(prepared):
        digest = hashlib.sha256(item.text.encode("utf-8")).hexdigest()
        try:
            verdict = pipeline.check(item.text)
        except Exception as exc:
            logger.error("Batch item %d check failed (%s)", index, type(exc).__name__)
            result.items.append(
                ItemResult(
                    index, item.id, item.source, digest, len(item.text),
                    STATE_DEGRADED, error=type(exc).__name__,
                )
            )
            continue
        result.items.append(
            ItemResult(
                index, item.id, item.source, digest, len(item.text),
                classify(verdict), verdict=verdict.to_dict(),
            )
        )
    return result


def read_jsonl(lines: Iterable[str]) -> Iterator[Any]:
    """Yield one item per non-blank line: a JSON string or object."""
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(f"line {number}: malformed JSON") from None
