"""
little_canary.ingest — experimental Ingest surface: screen records, admit or hold.

A thin, deterministic loop over ``SecurityPipeline.check`` that keeps three
states separate for every record:

* **detection** — what the detector observed on the material it actually checked
  (``none`` / ``flag`` / ``block``);
* **coverage** — how much of the record's material completed an exercised check
  (``complete`` / ``partial`` / ``none``);
* **admission** — the policy decision (``admitted`` / ``held``). Only admission is
  read by export.

A record is admitted only when every planned segment (text and metadata) completed
an exercised, non-degraded check with a ``pass`` state. Everything else is held with
explicit reasons. "Admitted" means the record completed the configured checks and
satisfied policy; it is not a statement that the content is harmless.

Held record text is never retained. The manifest carries only hashes, lengths,
offsets, states and provenance labels — never record text or metadata values.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import os
import tempfile
import types
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Callable

from . import batch
from .pipeline import PipelineVerdict

logger = logging.getLogger("little_canary.ingest")

MANIFEST_SCHEMA = "little-canary-ingest-manifest/v1"
EXPORT_SCHEMA = "little-canary-ingest-export/v1"
POLICY_NAME = "strict/v1"

# Detection (what the detector observed on the material it actually checked)
DETECTION_NONE = "none"
DETECTION_FLAG = "flag"
DETECTION_BLOCK = "block"
DETECTION_STATES = (DETECTION_NONE, DETECTION_FLAG, DETECTION_BLOCK)

# Coverage (how much of the record's material completed an exercised check)
COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_NONE = "none"
COVERAGE_STATES = (COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_NONE)

# Admission (policy decision; the only thing export reads)
ADMISSION_ADMITTED = "admitted"
ADMISSION_HELD = "held"

# Hold reasons (a held record lists every reason that applies, in this order)
HOLD_MALFORMED = "malformed"
HOLD_OVER_BUDGET = "over_budget"
HOLD_BLOCKED = "blocked"
HOLD_FLAGGED = "flagged"
HOLD_DEGRADED = "degraded"
HOLD_UNEXERCISED = "unexercised"
HOLD_ERROR = "error"
HOLD_INCOMPLETE = "incomplete"
HOLD_REASONS = (
    HOLD_MALFORMED,
    HOLD_OVER_BUDGET,
    HOLD_BLOCKED,
    HOLD_FLAGGED,
    HOLD_DEGRADED,
    HOLD_UNEXERCISED,
    HOLD_ERROR,
    HOLD_INCOMPLETE,
)

SEGMENT_TEXT = "text"
SEGMENT_METADATA = "metadata"
STATE_ERROR = "error"
STATE_NOT_CHECKED = "not_checked"

STATUS_COMPLETE = "complete"

MAX_METADATA_KEY_CHARS = 128
_MAX_DETAIL_CHARS = 200
_MAX_SIGNALS = 32
_MAX_SIGNAL_CHARS = 128
_RECORD_KEYS = frozenset({"text", "id", "source", "metadata"})
_EXPORT_RECORD_KEYS = frozenset(
    {"index", "id", "source", "sha256", "material_sha256", "metadata", "text"}
)
# States that end checking of a record when ``stop_after_hold`` is set.
_STOP_STATES = frozenset(
    {batch.STATE_BLOCK, batch.STATE_FLAG, batch.STATE_DEGRADED, batch.STATE_UNEXERCISED, STATE_ERROR}
)
_STATE_REASON = (
    (batch.STATE_BLOCK, HOLD_BLOCKED),
    (batch.STATE_FLAG, HOLD_FLAGGED),
    (batch.STATE_DEGRADED, HOLD_DEGRADED),
    (batch.STATE_UNEXERCISED, HOLD_UNEXERCISED),
    (STATE_ERROR, HOLD_ERROR),
)


# ---------------------------------------------------------------------------
# Policy and records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IngestPolicy:
    """Budget and stop rules for one ingest run (policy ``strict/v1``)."""

    segment_chars: int = 3500
    segment_overlap: int = 500
    max_segments: int = 8
    max_item_bytes: int = batch.DEFAULT_MAX_ITEM_BYTES
    max_items: int = batch.DEFAULT_MAX_ITEMS
    max_total_bytes: int = batch.DEFAULT_MAX_TOTAL_BYTES
    max_metadata_keys: int = 32
    max_metadata_value_chars: int = 1024
    stop_after_hold: bool = True

    def validate(self) -> None:
        """Raise ``ValueError`` for any out-of-range field."""
        batch.check_limit("segment_chars", self.segment_chars)
        if self.segment_chars < 1:
            raise ValueError("segment_chars must be at least 1")
        batch.check_limit("segment_overlap", self.segment_overlap)
        if self.segment_overlap >= self.segment_chars:
            raise ValueError("segment_overlap must be smaller than segment_chars")
        batch.check_limit("max_segments", self.max_segments)
        batch.check_limit("max_item_bytes", self.max_item_bytes, maximum=batch.MAX_ITEM_BYTES_CEILING)
        batch.check_limit("max_items", self.max_items)
        batch.check_limit("max_total_bytes", self.max_total_bytes)
        batch.check_limit("max_metadata_keys", self.max_metadata_keys)
        batch.check_limit("max_metadata_value_chars", self.max_metadata_value_chars)
        if not isinstance(self.stop_after_hold, bool):
            raise ValueError("stop_after_hold must be a bool")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": POLICY_NAME}
        for f in fields(self):
            out[f.name] = getattr(self, f.name)
        return out


@dataclass(frozen=True)
class IngestRecord:
    """One untrusted record: text plus provenance labels and string metadata.

    ``metadata`` is stored as an immutable copy when it is a mapping. Every field
    is attacker-controlled material and is validated and screened by ``ingest``.
    """

    text: str
    id: str | None = None
    source: str | None = None
    metadata: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.metadata, Mapping):
            object.__setattr__(self, "metadata", types.MappingProxyType(dict(self.metadata)))


@dataclass
class SegmentResult:
    kind: str
    index: int
    start: int
    end: int
    sha256: str
    state: str
    verdict: dict[str, Any] | None = None
    error: str | None = None
    latency: float | None = None
    exercised: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "index": self.index,
            "start": self.start,
            "end": self.end,
            "sha256": self.sha256,
            "state": self.state,
            "exercised": self.exercised,
            "verdict": dict(self.verdict) if self.verdict is not None else None,
            "error": self.error,
            "latency": self.latency,
        }


@dataclass
class RecordResult:
    """Per-record outcome. Carries no record text and no metadata values."""

    index: int
    id: str | None
    source: str | None
    length: int
    sha256: str
    material_sha256: str
    metadata_keys: list[str]
    detection: str
    detection_signals: list[str]
    coverage: str
    segments_total: int
    segments_checked: int
    chars_total: int
    chars_covered: int
    admission: str
    hold_reasons: list[str]
    segments: list[SegmentResult] = field(default_factory=list)
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "id": self.id,
            "source": self.source,
            "length": self.length,
            "sha256": self.sha256,
            "material_sha256": self.material_sha256,
            "metadata_keys": list(self.metadata_keys),
            "detection": self.detection,
            "detection_signals": list(self.detection_signals),
            "coverage": self.coverage,
            "segments_total": self.segments_total,
            "segments_checked": self.segments_checked,
            "chars_total": self.chars_total,
            "chars_covered": self.chars_covered,
            "admission": self.admission,
            "hold_reasons": list(self.hold_reasons),
            "detail": self.detail,
            "segments": [s.to_dict() for s in self.segments],
        }


@dataclass
class AdmittedRecord:
    """The only place ingest retains text, and only for admitted records."""

    index: int
    id: str | None
    source: str | None
    text: str
    metadata: dict[str, str]
    sha256: str
    material_sha256: str

    def to_export_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "id": self.id,
            "source": self.source,
            "sha256": self.sha256,
            "material_sha256": self.material_sha256,
            "metadata": dict(self.metadata),
            "text": self.text,
        }


def _canonical_json(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class IngestResult:
    records: list[RecordResult]
    admitted: list[AdmittedRecord]
    policy: IngestPolicy
    pipeline_info: dict[str, Any]
    started_at: str
    finished_at: str
    checks_performed: int
    status: str = STATUS_COMPLETE

    @property
    def counts(self) -> dict[str, Any]:
        by_reason = dict.fromkeys(HOLD_REASONS, 0)
        detection = dict.fromkeys(DETECTION_STATES, 0)
        coverage = dict.fromkeys(COVERAGE_STATES, 0)
        admitted = 0
        for rec in self.records:
            if rec.admission == ADMISSION_ADMITTED:
                admitted += 1
            for reason in rec.hold_reasons:
                by_reason[reason] += 1
            detection[rec.detection] += 1
            coverage[rec.coverage] += 1
        return {
            "admitted": admitted,
            "held": len(self.records) - admitted,
            "by_reason": by_reason,
            "detection": detection,
            "coverage": coverage,
        }

    def manifest(self) -> dict[str, Any]:
        """Evidence document for the run. Contains no record text or metadata values."""
        from . import __version__  # lazy: the package imports this module first

        return {
            "schema": MANIFEST_SCHEMA,
            "little_canary_version": __version__,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pipeline": dict(self.pipeline_info),
            "policy": self.policy.to_dict(),
            "run": {
                "status": self.status,
                "records_total": len(self.records),
                "checks_performed": self.checks_performed,
            },
            "counts": self.counts,
            "records": [rec.to_dict() for rec in self.records],
        }

    def manifest_json(self) -> str:
        """Canonical manifest serialization; this is what export hashes."""
        return _canonical_json(self.manifest())

    def export_document(self) -> dict[str, Any]:
        """Admitted records only, bound to the manifest by SHA-256."""
        if self.status != STATUS_COMPLETE:
            raise ValueError("export requires a complete ingest run")
        return {
            "schema": EXPORT_SCHEMA,
            "manifest_schema": MANIFEST_SCHEMA,
            "manifest_sha256": _sha256_text(self.manifest_json()),
            "policy_name": POLICY_NAME,
            "records": [rec.to_export_dict() for rec in self.admitted],
        }


# ---------------------------------------------------------------------------
# Pure helpers: segmentation, metadata material, hashing
# ---------------------------------------------------------------------------


def segment_text(text: str, segment_chars: int, overlap: int) -> list[tuple[int, int]]:
    """Deterministic ``[start, end)`` plan whose union covers ``[0, len(text))``.

    stride = segment_chars - overlap; n = 1 + max(0, ceil((len - segment_chars) / stride));
    segment i = [i*stride, min(i*stride + segment_chars, len)). Empty text has no segments.
    """
    if segment_chars < 1 or overlap < 0 or overlap >= segment_chars:
        raise ValueError("segment_chars must be >= 1 and 0 <= overlap < segment_chars")
    length = len(text)
    if length == 0:
        return []
    stride = segment_chars - overlap
    count = 1 + max(0, math.ceil((length - segment_chars) / stride))
    return [(i * stride, min(i * stride + segment_chars, length)) for i in range(count)]


def _metadata_lines(
    id_: str | None, source: str | None, metadata: Mapping[str, str]
) -> list[str]:
    lines = []
    if id_ is not None:
        lines.append(f"id: {id_}")
    if source is not None:
        lines.append(f"source: {source}")
    lines.extend(f"{k}: {v}" for k, v in sorted(metadata.items()))
    return lines


def metadata_material(record: IngestRecord) -> str:
    """Canonical text of everything besides ``text`` that export emits.

    Lines ``id: <id>`` and ``source: <source>`` (when present) come first, then
    ``<key>: <value>`` for each metadata key in sorted order, joined by ``\\n``.
    Returns ``""`` when the record has no id, source or metadata.
    """
    return "\n".join(_metadata_lines(record.id, record.source, record.metadata or {}))


def _material_sha256(
    id_: Any, source: Any, metadata: Mapping[str, Any], text: str
) -> str:
    doc = {
        "id": id_,
        "source": source,
        "metadata": dict(sorted(metadata.items())),
        "text": text,
    }
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _union_length(ranges: list[tuple[int, int]]) -> int:
    total = 0
    cur_start = cur_end = -1
    for start, end in sorted(ranges):
        if start > cur_end:
            total += max(0, cur_end - cur_start)
            cur_start, cur_end = start, end
        else:
            cur_end = max(cur_end, end)
    total += max(0, cur_end - cur_start)
    return total


def read_records(
    source: Iterable[str] | Any,
    *,
    max_item_bytes: int = batch.DEFAULT_MAX_ITEM_BYTES,
    max_metadata_keys: int = 32,
    max_metadata_value_chars: int = 1024,
) -> Iterator[Any]:
    """Yield one raw record per non-blank JSONL line, with a bounded line length.

    The line cap is ``batch.max_line_chars(max_item_bytes)`` plus room for a
    worst-case escaped metadata object within the metadata limits, so a record
    that is within every limit is never rejected by the reader.
    """
    batch.check_limit("max_item_bytes", max_item_bytes, maximum=batch.MAX_ITEM_BYTES_CEILING)
    batch.check_limit("max_metadata_keys", max_metadata_keys)
    batch.check_limit("max_metadata_value_chars", max_metadata_value_chars)
    slack = max_metadata_keys * (12 * (MAX_METADATA_KEY_CHARS + max_metadata_value_chars) + 8) + 16
    return batch.read_jsonl(source, max_line=batch.max_line_chars(max_item_bytes) + slack)


# ---------------------------------------------------------------------------
# Record preparation (validation + snapshot, before any check)
# ---------------------------------------------------------------------------


@dataclass
class _Prepared:
    index: int
    text: Any
    id: Any
    source: Any
    metadata: Any
    malformed: str | None = None


def _snapshot(raw: Any, index: int) -> _Prepared:
    """Read every field exactly once into a private snapshot; shape errors are run-level."""
    if isinstance(raw, IngestRecord):
        return _Prepared(index, raw.text, raw.id, raw.source, raw.metadata)
    if isinstance(raw, batch.BatchItem):
        return _Prepared(index, raw.text, raw.id, raw.source, None)
    if isinstance(raw, str):
        return _Prepared(index, raw, None, None, None)
    if isinstance(raw, Mapping):
        snap = dict(raw)
        prepared = _Prepared(
            index, snap.get("text"), snap.get("id"), snap.get("source"), snap.get("metadata")
        )
        if any(not isinstance(k, str) or k not in _RECORD_KEYS for k in snap):
            prepared.malformed = f"record {index}: unknown_keys"
        return prepared
    raise ValueError(
        f"record {index}: must be a string, object, IngestRecord or BatchItem"
    )


def _encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _validate_metadata(meta: Any, index: int, policy: IngestPolicy) -> str | None:
    if meta is None:
        return None
    if not isinstance(meta, Mapping):
        return f"record {index}: 'metadata' must be an object"
    if len(meta) > policy.max_metadata_keys:
        return f"record {index}: 'metadata' exceeds {policy.max_metadata_keys} keys"
    for key, value in meta.items():
        if not isinstance(key, str) or key == "" or len(key) > MAX_METADATA_KEY_CHARS:
            return f"record {index}: metadata keys must be non-empty strings of at most {MAX_METADATA_KEY_CHARS} characters"
        if not _encodable(key):
            return f"record {index}: metadata key is not valid Unicode (lone surrogate)"
        if not isinstance(value, str):
            return f"record {index}: metadata values must be strings"
        if len(value) > policy.max_metadata_value_chars:
            return f"record {index}: metadata value exceeds {policy.max_metadata_value_chars} characters"
        if not _encodable(value):
            return f"record {index}: metadata value is not valid Unicode (lone surrogate)"
    return None


def _valid_label(value: Any) -> str | None:
    """Return a provenance label only if it would itself pass validation."""
    if isinstance(value, str) and len(value) <= batch.MAX_LABEL_CHARS and _encodable(value):
        return value
    return None


def _text_bytes_for_budget(text: Any, remaining: int) -> int | None:
    """UTF-8 size of ``text`` (lone surrogates counted as 3 bytes), or None if not a str.

    Returns ``remaining + 1`` without encoding when the char count alone already exceeds it.
    """
    if not isinstance(text, str):
        return None
    if len(text) > remaining:
        return remaining + 1
    return len(text.encode("utf-8", "surrogatepass"))


# ---------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------


def _is_exercised(verdict: PipelineVerdict) -> bool:
    return (
        verdict.degraded is False
        and verdict.canary_status == "exercised"
        and verdict.analysis_status == "exercised"
        and verdict.canary_risk_score is not None
    )


def _signals(verdict: PipelineVerdict) -> list[str]:
    out = []
    if isinstance(verdict.blocked_by, str):
        out.append(verdict.blocked_by[:_MAX_SIGNAL_CHARS])
    advisory = verdict.advisory
    if advisory is not None and getattr(advisory, "flagged", False):
        raw = getattr(advisory, "signals", None)
        if isinstance(raw, (list, tuple)):
            out.extend(s[:_MAX_SIGNAL_CHARS] for s in raw if isinstance(s, str))
    return out


def _pipeline_info(pipeline: Any) -> dict[str, Any]:
    def prim(value: Any) -> Any:
        return value if isinstance(value, (str, bool)) or value is None else None

    use_judge = getattr(pipeline, "use_judge", None)
    analysis = None if not isinstance(use_judge, bool) else ("judge" if use_judge else "regex")
    return {
        "mode": prim(getattr(pipeline, "mode", None)),
        "provider": prim(getattr(pipeline, "provider", None)),
        "canary_model": prim(getattr(getattr(pipeline, "canary_probe", None), "model", None)),
        "analysis_method": analysis,
        "structural_filter": prim(getattr(pipeline, "enable_structural_filter", None)),
        "canary_enabled": prim(getattr(pipeline, "enable_canary", None)),
    }


def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _held_without_checks(
    prepared: _Prepared,
    reason: str,
    *,
    detail: str | None = None,
    segments_total: int = 0,
    chars_total: int = 0,
    sha256: str = "",
    material_sha256: str = "",
    metadata_keys: list[str] | None = None,
) -> RecordResult:
    text = prepared.text
    return RecordResult(
        index=prepared.index,
        id=_valid_label(prepared.id),
        source=_valid_label(prepared.source),
        length=len(text) if isinstance(text, str) else 0,
        sha256=sha256,
        material_sha256=material_sha256,
        metadata_keys=metadata_keys or [],
        detection=DETECTION_NONE,
        detection_signals=[],
        coverage=COVERAGE_NONE,
        segments_total=segments_total,
        segments_checked=0,
        chars_total=chars_total,
        chars_covered=0,
        admission=ADMISSION_HELD,
        hold_reasons=[reason],
        segments=[],
        detail=detail[:_MAX_DETAIL_CHARS] if detail else None,
    )


class _Counter:
    def __init__(self) -> None:
        self.calls = 0


def _check_segment(
    pipeline: Any, kind: str, index: int, material: str, span: tuple[int, int], counter: _Counter
) -> tuple[SegmentResult, list[str]]:
    start, end = span
    piece = material[start:end]
    seg = SegmentResult(kind, index, start, end, _sha256_text(piece), STATE_ERROR)
    counter.calls += 1
    try:
        verdict = pipeline.check(piece)
        if not isinstance(verdict, PipelineVerdict):
            raise TypeError("pipeline.check returned a non-PipelineVerdict")
        state = batch.classify(verdict)
        # redacted at construction: the in-memory result never retains raw text
        payload = {k: v for k, v in verdict.to_dict().items() if k not in batch._RAW_TEXT_KEYS}
        exercised = _is_exercised(verdict)
        signals = _signals(verdict)
        latency = float(verdict.total_latency)
    except Exception as exc:  # BaseException (e.g. KeyboardInterrupt) propagates
        logger.error("Ingest segment check failed (%s)", type(exc).__name__)
        seg.error = type(exc).__name__
        return seg, []
    seg.state = state
    seg.verdict = payload
    seg.exercised = exercised
    seg.latency = latency
    return seg, signals


def _screen_record(
    pipeline: Any,
    prepared: _Prepared,
    metadata: dict[str, str],
    text_plan: list[tuple[int, int]],
    meta_text: str,
    meta_plan: list[tuple[int, int]],
    policy: IngestPolicy,
    counter: _Counter,
    sha256: str,
    material_sha256: str,
) -> tuple[RecordResult, bool]:
    text: str = prepared.text
    planned: list[tuple[str, int, str, tuple[int, int]]] = [
        (SEGMENT_METADATA, i, meta_text, span) for i, span in enumerate(meta_plan)
    ] + [(SEGMENT_TEXT, i, text, span) for i, span in enumerate(text_plan)]

    segments: list[SegmentResult] = []
    signals: set[str] = set()
    stopped = False
    for kind, i, material, span in planned:
        if stopped:
            segments.append(
                SegmentResult(kind, i, span[0], span[1], _sha256_text(material[span[0]:span[1]]),
                              STATE_NOT_CHECKED)
            )
            continue
        seg, seg_signals = _check_segment(pipeline, kind, i, material, span, counter)
        signals.update(seg_signals)
        segments.append(seg)
        if policy.stop_after_hold and seg.state in _STOP_STATES:
            stopped = True

    states = {s.state for s in segments}
    if batch.STATE_BLOCK in states:
        detection = DETECTION_BLOCK
    elif batch.STATE_FLAG in states:
        detection = DETECTION_FLAG
    else:
        detection = DETECTION_NONE

    exercised = [s for s in segments if s.exercised]
    if len(exercised) == len(segments):
        coverage = COVERAGE_COMPLETE
    elif not exercised:
        coverage = COVERAGE_NONE
    else:
        coverage = COVERAGE_PARTIAL

    reasons = [reason for state, reason in _STATE_REASON if state in states]
    if STATE_NOT_CHECKED in states or coverage != COVERAGE_COMPLETE:
        reasons.append(HOLD_INCOMPLETE)

    covered = _union_length([(s.start, s.end) for s in exercised if s.kind == SEGMENT_TEXT]) + \
        _union_length([(s.start, s.end) for s in exercised if s.kind == SEGMENT_METADATA])

    admitted = not reasons
    # Defence in depth: admission must imply every separate state is clean.
    if admitted and not (
        detection == DETECTION_NONE
        and coverage == COVERAGE_COMPLETE
        and all(s.state == batch.STATE_PASS for s in segments)
    ):  # pragma: no cover - unreachable by construction
        reasons.append(HOLD_INCOMPLETE)
        admitted = False

    result = RecordResult(
        index=prepared.index,
        id=prepared.id,
        source=prepared.source,
        length=len(text),
        sha256=sha256,
        material_sha256=material_sha256,
        metadata_keys=sorted(metadata),
        detection=detection,
        detection_signals=sorted(signals)[:_MAX_SIGNALS],
        coverage=coverage,
        segments_total=len(planned),
        segments_checked=len(exercised),
        chars_total=len(text) + len(meta_text),
        chars_covered=covered,
        admission=ADMISSION_ADMITTED if admitted else ADMISSION_HELD,
        hold_reasons=reasons,
        segments=segments,
    )
    return result, admitted


def ingest_records(
    pipeline: Any,
    records: Iterable[Any],
    *,
    policy: IngestPolicy | None = None,
    now: Callable[[], datetime] | None = None,
) -> IngestResult:
    """Screen every record's material and decide admission under ``policy``.

    All records are read, snapshotted and budgeted before any check runs.
    Run-level ``ValueError`` (nothing checked, nothing returned): invalid policy,
    ``segment_chars`` above the pipeline's structural ``max_input_length``, more
    than ``max_items`` records, summed text bytes above ``max_total_bytes``, or a
    record that is not a string/object/IngestRecord/BatchItem. Record-level
    problems are held records, never run failures. ``KeyboardInterrupt`` and other
    ``BaseException`` propagate, so no partial result exists.
    """
    policy = policy if policy is not None else IngestPolicy()
    if not isinstance(policy, IngestPolicy):
        raise ValueError("policy must be an IngestPolicy")
    policy.validate()
    limit = getattr(getattr(pipeline, "structural_filter", None), "max_input_length", None)
    if isinstance(limit, int) and not isinstance(limit, bool) and policy.segment_chars > limit:
        raise ValueError(
            f"segment_chars ({policy.segment_chars}) exceeds the pipeline's max_input_length ({limit})"
        )
    clock = now if now is not None else (lambda: datetime.now(timezone.utc))

    # Phase 1: snapshot + run-level budget, before any check.
    prepared: list[_Prepared] = []
    total = 0
    for raw in records:
        if len(prepared) >= policy.max_items:
            raise ValueError(f"ingest exceeds the limit of {policy.max_items} records")
        item = _snapshot(raw, len(prepared))
        size = _text_bytes_for_budget(item.text, policy.max_total_bytes - total)
        if size is not None:
            total += size
            if total > policy.max_total_bytes:
                raise ValueError(f"ingest exceeds the limit of {policy.max_total_bytes} total bytes")
        prepared.append(item)

    started_at = _iso_utc(clock())
    counter = _Counter()
    results: list[RecordResult] = []
    admitted: list[AdmittedRecord] = []

    # Phase 2: per-record validation, planning, screening.
    for item in prepared:
        if item.malformed is not None:
            results.append(_held_without_checks(item, HOLD_MALFORMED, detail=item.malformed))
            continue
        # Reuse batch validation for text/id/source, but with a byte bound no valid
        # string can exceed: over-size text is an over-budget hold, not malformed.
        no_byte_bound = max(policy.max_item_bytes, 4 * len(item.text) if isinstance(item.text, str) else 0)
        try:
            batch.coerce_item(
                batch.BatchItem(text=item.text, id=item.id, source=item.source),
                item.index,
                max_item_bytes=no_byte_bound,
            )
        except ValueError as exc:
            results.append(_held_without_checks(item, HOLD_MALFORMED, detail=str(exc)))
            continue
        problem = _validate_metadata(item.metadata, item.index, policy)
        if problem is not None:
            results.append(_held_without_checks(item, HOLD_MALFORMED, detail=problem))
            continue

        text: str = item.text
        metadata: dict[str, str] = dict(item.metadata) if item.metadata is not None else {}
        meta_text = "\n".join(_metadata_lines(item.id, item.source, metadata))
        text_plan = segment_text(text, policy.segment_chars, policy.segment_overlap)
        meta_plan = (
            segment_text(meta_text, policy.segment_chars, policy.segment_overlap) if meta_text else []
        )
        text_bytes = len(text.encode("utf-8"))
        sha256 = _sha256_text(text)
        material_sha256 = _material_sha256(item.id, item.source, metadata, text)
        planned = len(text_plan) + len(meta_plan)
        if text_bytes > policy.max_item_bytes or planned > policy.max_segments:
            detail = (
                f"record {item.index}: text exceeds {policy.max_item_bytes} bytes"
                if text_bytes > policy.max_item_bytes
                else f"record {item.index}: needs {planned} segments, limit {policy.max_segments}"
            )
            results.append(
                _held_without_checks(
                    item, HOLD_OVER_BUDGET, detail=detail, segments_total=planned,
                    chars_total=len(text) + len(meta_text), sha256=sha256,
                    material_sha256=material_sha256, metadata_keys=sorted(metadata),
                )
            )
            continue

        record, ok = _screen_record(
            pipeline, item, metadata, text_plan, meta_text, meta_plan, policy, counter,
            sha256, material_sha256,
        )
        results.append(record)
        if ok:
            admitted.append(
                AdmittedRecord(item.index, item.id, item.source, text, metadata, sha256, material_sha256)
            )

    return IngestResult(
        records=results,
        admitted=admitted,
        policy=policy,
        pipeline_info=_pipeline_info(pipeline),
        started_at=started_at,
        finished_at=_iso_utc(clock()),
        checks_performed=counter.calls,
        status=STATUS_COMPLETE,
    )


# ---------------------------------------------------------------------------
# Atomic writers
# ---------------------------------------------------------------------------


def _atomic_write(path: str | os.PathLike[str], data: bytes, *, overwrite: bool) -> str:
    target = os.fspath(path)
    if not overwrite and os.path.lexists(target):
        raise FileExistsError(f"refusing to overwrite existing file: {target}")
    directory = os.path.dirname(os.path.abspath(target))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(target) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    try:  # best-effort durability of the rename; not available everywhere
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        pass
    else:
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)
    return hashlib.sha256(data).hexdigest()


def write_manifest(
    result: IngestResult, path: str | os.PathLike[str], *, overwrite: bool = False
) -> str:
    """Atomically write ``result.manifest_json()``; return the SHA-256 of the bytes written.

    The written bytes are exactly the canonical manifest, so the returned digest
    equals the export's ``manifest_sha256``.
    """
    return _atomic_write(path, result.manifest_json().encode("utf-8"), overwrite=overwrite)


def write_export(
    result: IngestResult, path: str | os.PathLike[str], *, overwrite: bool = False
) -> str:
    """Atomically write the export (admitted records only); return SHA-256 of the bytes."""
    if result.status != STATUS_COMPLETE:
        raise ValueError("export requires a complete ingest run")
    data = _canonical_json(result.export_document()).encode("utf-8")
    return _atomic_write(path, data, overwrite=overwrite)


# ---------------------------------------------------------------------------
# Consumer-side verification
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def verify_export(export_doc: Any, manifest: Any) -> list[str]:
    """Return every inconsistency between an export and its manifest ([] = consistent).

    Checks schemas, the manifest hash binding, that every exported record is
    admitted in the manifest with complete coverage and no detection, that the
    exported set equals the admitted set, and that ``sha256``/``material_sha256``
    recomputed from the exported text and metadata match. Problems name record
    indices only, never text.
    """
    problems: list[str] = []
    if not isinstance(export_doc, dict):
        return ["export is not an object"]
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    if export_doc.get("schema") != EXPORT_SCHEMA:
        problems.append("export schema mismatch")
    if export_doc.get("manifest_schema") != MANIFEST_SCHEMA or manifest.get("schema") != MANIFEST_SCHEMA:
        problems.append("manifest schema mismatch")
    try:
        digest = _sha256_text(_canonical_json(manifest))
    except (TypeError, ValueError):
        digest = None
    if digest is None or export_doc.get("manifest_sha256") != digest:
        problems.append("manifest_sha256 does not match the manifest")
    policy = manifest.get("policy")
    if export_doc.get("policy_name") != POLICY_NAME or not (
        isinstance(policy, dict) and policy.get("name") == export_doc.get("policy_name")
    ):
        problems.append("policy name mismatch")
    run = manifest.get("run")
    if not (isinstance(run, dict) and run.get("status") == STATUS_COMPLETE):
        problems.append("manifest run is not complete")

    by_index: dict[int, dict[str, Any]] = {}
    manifest_records = manifest.get("records")
    if not isinstance(manifest_records, list):
        problems.append("manifest records missing")
        manifest_records = []
    for rec in manifest_records:
        if isinstance(rec, dict) and _is_int(rec.get("index")):
            by_index[rec["index"]] = rec
    admitted_indices = {
        i for i, rec in by_index.items() if rec.get("admission") == ADMISSION_ADMITTED
    }

    export_records = export_doc.get("records")
    if not isinstance(export_records, list):
        problems.append("export records missing")
        return problems
    seen: set[int] = set()
    for pos, rec in enumerate(export_records):
        if not isinstance(rec, dict) or not _is_int(rec.get("index")):
            problems.append(f"export record at position {pos}: malformed")
            continue
        idx = rec["index"]
        label = f"record {idx}"
        if set(rec) != _EXPORT_RECORD_KEYS:
            problems.append(f"{label}: unexpected or missing fields")
        if idx in seen:
            problems.append(f"{label}: duplicated in export")
        seen.add(idx)
        mrec = by_index.get(idx)
        if mrec is None:
            problems.append(f"{label}: not in manifest")
            continue
        if (
            mrec.get("admission") != ADMISSION_ADMITTED
            or mrec.get("hold_reasons") != []
            or mrec.get("coverage") != COVERAGE_COMPLETE
            or mrec.get("detection") != DETECTION_NONE
        ):
            problems.append(f"{label}: not admitted in manifest")
        text = rec.get("text")
        metadata = rec.get("metadata")
        if not isinstance(text, str) or not _encodable(text):
            problems.append(f"{label}: text missing or invalid")
            continue
        if not isinstance(metadata, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and _encodable(k) and _encodable(v)
            for k, v in metadata.items()
        ):
            problems.append(f"{label}: metadata invalid")
            continue
        sha = _sha256_text(text)
        if rec.get("sha256") != sha or mrec.get("sha256") != sha:
            problems.append(f"{label}: sha256 mismatch")
        if mrec.get("length") != len(text):
            problems.append(f"{label}: length mismatch")
        material = _material_sha256(rec.get("id"), rec.get("source"), metadata, text)
        if rec.get("material_sha256") != material or mrec.get("material_sha256") != material:
            problems.append(f"{label}: material_sha256 mismatch")
        if rec.get("id") != mrec.get("id") or rec.get("source") != mrec.get("source"):
            problems.append(f"{label}: provenance mismatch")
        if sorted(metadata) != mrec.get("metadata_keys"):
            problems.append(f"{label}: metadata keys mismatch")
    missing = admitted_indices - seen
    if missing:
        problems.append(f"admitted records missing from export: {sorted(missing)}")
    counts = manifest.get("counts")
    if not (isinstance(counts, dict) and counts.get("admitted") == len(export_records)):
        problems.append("export record count does not match manifest admitted count")
    return problems
