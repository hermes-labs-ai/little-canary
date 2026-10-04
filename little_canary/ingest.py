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

Held record text is never retained. The manifest carries hashes, lengths,
offsets, states, detector-generated signals and verdict summaries, and — for
admitted records only — the plaintext ``id``/``source`` labels and metadata key
names (they were screened and passed). For held records the labels are replaced
by their SHA-256 digests and the key names by a key count. Record text and
metadata values never appear in the manifest.
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
from .pipeline import PipelineVerdict, SecurityPipeline

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
        batch.check_limit("segment_chars", self.segment_chars, maximum=batch.MAX_ITEM_BYTES_CEILING)
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
            # Single read of the caller's mapping. Keys must be unique plain str: a
            # repeated or look-alike key would otherwise be merged here, which is a
            # silent rewrite of the record before screening. Such a record is kept
            # as invalid metadata so ingest holds it as malformed (never merged).
            copied: dict[Any, Any] = {}
            problem: str | None = None
            for key, value in self.metadata.items():
                if not _exact_str(key):
                    problem = problem or "metadata keys must be plain str"
                    continue
                if key in copied:
                    problem = problem or "metadata keys collide"
                    continue
                copied[key] = value
            if problem is not None:
                object.__setattr__(self, "metadata", _InvalidMetadata(problem))
            else:
                object.__setattr__(self, "metadata", types.MappingProxyType(copied))


@dataclass(frozen=True)
class _InvalidMetadata:
    """Placeholder kept on an ``IngestRecord`` whose metadata keys were not unique plain str."""

    reason: str


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
    id: str | None                 # plaintext only for admitted records; None when held
    source: str | None             # plaintext only for admitted records; None when held
    length: int
    sha256: str
    material_sha256: str
    metadata_keys: list[str] | None  # sorted key names, admitted records only; None when held
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
    id_sha256: str | None = None       # digest of the label when it is a valid label; else None
    source_sha256: str | None = None
    metadata_key_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "id": self.id,
            "source": self.source,
            "id_sha256": self.id_sha256,
            "source_sha256": self.source_sha256,
            "length": self.length,
            "sha256": self.sha256,
            "material_sha256": self.material_sha256,
            "metadata_keys": list(self.metadata_keys) if self.metadata_keys is not None else None,
            "metadata_key_count": self.metadata_key_count,
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
    input_sha256: str | None = None     # digest of the exact input bytes, when the caller read them all
    export_requested: bool = False      # recorded so a manifest without its export is detectable

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
                "input_sha256": self.input_sha256,
                "export_requested": self.export_requested,
            },
            "counts": self.counts,
            "records": [rec.to_dict() for rec in self.records],
        }

    def manifest_json(self) -> str:
        """Canonical manifest serialization; this is what export hashes."""
        return _canonical_json(self.manifest())

    def export_document(self) -> dict[str, Any]:
        """Admitted records only, bound to the manifest by SHA-256.

        Raises ``ValueError`` if the in-memory result is inconsistent: every
        admitted entry must match a record with admission ``admitted`` and the
        same hashes, and every admitted record must have an entry.
        """
        if self.status != STATUS_COMPLETE:
            raise ValueError("export requires a complete ingest run")
        # Producing an export binds it to a manifest that records the request, so a
        # manifest on disk whose export is missing is detectable. Write the manifest
        # after this call (or use ``publish``), never before.
        self.export_requested = True
        by_index = {rec.index: rec for rec in self.records}
        admitted_indices = {rec.index for rec in self.records if rec.admission == ADMISSION_ADMITTED}
        seen: set[int] = set()
        for entry in self.admitted:
            rec = by_index.get(entry.index)
            if (
                rec is None
                or entry.index in seen
                or rec.admission != ADMISSION_ADMITTED
                or rec.hold_reasons
                or rec.sha256 != entry.sha256
                or rec.material_sha256 != entry.material_sha256
                or rec.sha256 != _sha256_text(entry.text)
                or rec.id != entry.id
                or rec.source != entry.source
                or rec.metadata_keys != sorted(entry.metadata)
                or rec.material_sha256 != _material_sha256(entry.id, entry.source, entry.metadata, entry.text)
            ):
                raise ValueError(f"export refused: admitted entry {entry.index} does not match the run's records")
            seen.add(entry.index)
        if seen != admitted_indices:
            raise ValueError("export refused: admitted entries do not match the run's records")
        return {
            "schema": EXPORT_SCHEMA,
            "manifest_schema": MANIFEST_SCHEMA,
            "manifest_sha256": _sha256_text(self.manifest_json()),
            "policy_name": POLICY_NAME,
            "records": [rec.to_export_dict() for rec in sorted(self.admitted, key=lambda r: r.index)],
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
    if isinstance(record.metadata, _InvalidMetadata):
        raise ValueError(record.metadata.reason)
    metadata = {k: _plain(v) for k, v in (record.metadata or {}).items()}
    return "\n".join(_metadata_lines(_plain(record.id), _plain(record.source), metadata))


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


def _covered_chars(segments: list[SegmentResult]) -> int:
    """Characters whose owning segment completed an exercised check.

    Each segment owns the characters from its start up to the next segment's
    start (the last segment owns up to its end), so overlaps are attributed
    exactly once and ``chars_covered == chars_total`` holds iff every segment
    was exercised. An unexercised window in the middle is never masked by the
    overlap of its neighbours.
    """
    total = 0
    for kind in (SEGMENT_METADATA, SEGMENT_TEXT):
        ordered = sorted((s for s in segments if s.kind == kind), key=lambda s: s.start)
        for pos, seg in enumerate(ordered):
            if not seg.exercised:
                continue
            own_end = ordered[pos + 1].start if pos + 1 < len(ordered) else seg.end
            total += max(0, min(own_end, seg.end) - seg.start)
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
    worst-case escaped metadata object within the metadata limits, so a compactly
    serialized record within every limit is never rejected by the reader (a line
    padded with extra JSON whitespace can still exceed the cap). Unlike
    ``batch.read_jsonl``, an object with a duplicate key (at any depth) is
    malformed JSON: a parser that keeps the other value would screen and export
    different material, so the ambiguity is refused instead of resolved.
    """
    batch.check_limit("max_item_bytes", max_item_bytes, maximum=batch.MAX_ITEM_BYTES_CEILING)
    batch.check_limit("max_metadata_keys", max_metadata_keys)
    batch.check_limit("max_metadata_value_chars", max_metadata_value_chars)
    slack = max_metadata_keys * (12 * (MAX_METADATA_KEY_CHARS + max_metadata_value_chars) + 8) + 16
    return _read_strict_jsonl(source, batch.max_line_chars(max_item_bytes) + slack)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def loads_strict(text: str) -> Any:
    """``json.loads`` that rejects duplicate object keys at any depth."""
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


def _read_strict_jsonl(source: Any, max_line: int) -> Iterator[Any]:
    def parse(line: str, number: int) -> Any:
        try:
            return loads_strict(line)
        except (json.JSONDecodeError, RecursionError, ValueError):
            raise ValueError(f"line {number}: malformed JSON") from None

    number = 0
    if hasattr(source, "readline"):
        while True:
            line = source.readline(max_line + 1)
            if line == "":
                return
            number += 1
            if len(line) > max_line:
                raise ValueError(f"line {number}: exceeds {max_line} characters")
            if line.strip():
                yield parse(line, number)
    else:
        for number, line in enumerate(source, 1):
            if len(line) > max_line:
                raise ValueError(f"line {number}: exceeds {max_line} characters")
            if line.strip():
                yield parse(line, number)


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


def _exact_str(value: Any) -> bool:
    """True only for a plain ``str``: subclasses can lie about length, slicing, encoding."""
    return type(value) is str


def _plain(value: Any) -> Any:
    """Copy any ``str`` (including subclasses) into a plain ``str`` of its real contents.

    A ``str`` subclass can override ``__len__``, ``__getitem__``, ``encode`` or
    ``__str__`` so that what is budgeted, segmented, checked or hashed differs from
    what would be exported. The copy is made once, before any check, and is the
    only value ever validated, screened, hashed and exported. Non-strings pass
    through unchanged so validation can reject them.
    """
    if isinstance(value, str) and not _exact_str(value):
        return str.__getitem__(value, slice(None))
    return value


def _snapshot(raw: Any, index: int) -> _Prepared:
    """Read every field exactly once into a private snapshot; shape errors are run-level.

    Text, labels, metadata keys and values are copied into plain ``str`` values
    (see ``_plain``) and metadata is copied exactly once, here, before any check
    runs; validation, screening, hashing and export all use these copies.
    """
    if isinstance(raw, IngestRecord):
        prepared = _Prepared(index, raw.text, raw.id, raw.source, raw.metadata)
        if isinstance(raw.metadata, _InvalidMetadata):
            prepared.malformed = f"record {index}: {raw.metadata.reason}"
            prepared.metadata = None
    elif isinstance(raw, batch.BatchItem):
        prepared = _Prepared(index, raw.text, raw.id, raw.source, None)
    elif isinstance(raw, str):
        prepared = _Prepared(index, raw, None, None, None)
    elif isinstance(raw, Mapping):
        snap: dict[Any, Any] = {}
        yielded = 0
        for key, value in raw.items():  # single read; a repeated key is a rewrite, never merged
            yielded += 1
            snap[key] = value
        prepared = _Prepared(
            index, snap.get("text"), snap.get("id"), snap.get("source"), snap.get("metadata")
        )
        if any(not _exact_str(k) or k not in _RECORD_KEYS for k in snap):
            prepared.malformed = f"record {index}: unknown_keys"
        elif len(snap) != yielded:
            prepared.malformed = f"record {index}: keys collide"
    else:
        raise ValueError(
            f"record {index}: must be a string, object, IngestRecord or BatchItem"
        )
    if isinstance(prepared.metadata, Mapping):
        # The one and only read of the caller's mapping, taken before any check.
        # Keys must already be plain str: a str-subclass key with custom equality
        # could collide with another key and be silently merged (a rewrite).
        copied: dict[Any, Any] = {}
        yielded = 0
        for key, value in prepared.metadata.items():
            yielded += 1
            if not _exact_str(key):
                if prepared.malformed is None:
                    prepared.malformed = f"record {index}: metadata keys must be plain str"
                continue
            copied[key] = _plain(value)
        if len(copied) != yielded and prepared.malformed is None:
            prepared.malformed = f"record {index}: metadata keys collide"
        prepared.metadata = copied
    prepared.text = _plain(prepared.text)
    prepared.id = _plain(prepared.id)
    prepared.source = _plain(prepared.source)
    return prepared


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
        if not _exact_str(key) or key == "" or len(key) > MAX_METADATA_KEY_CHARS:
            return f"record {index}: metadata keys must be non-empty strings of at most {MAX_METADATA_KEY_CHARS} characters"
        if not _encodable(key):
            return f"record {index}: metadata key is not valid Unicode (lone surrogate)"
        if not _exact_str(value):
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


def _finite_real(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False  # an integer too large for a float is not a usable risk score


def _classify_payload(payload: Mapping[str, Any]) -> tuple[str, bool]:
    """Map one recorded verdict payload to ``(state, exercised)``.

    Decided from the single ``to_dict()`` snapshot that the manifest records, so
    admission is always supported by the recorded evidence. Mistyped or
    self-contradictory verdicts (non-bool flags, a ``blocked_by`` on a passing
    verdict, a non-finite or mistyped risk score, a non-bool advisory flag) are
    ``error``. State mirrors ``batch.classify`` precedence; ``exercised`` is the
    separate coverage fact: not degraded, canary and analysis both exercised, and
    a finite risk score was measured (true for a canary block or flag, false for
    a structural block that skipped the canary).
    """
    safe = payload.get("safe")
    degraded = payload.get("degraded")
    if not isinstance(safe, bool) or not isinstance(degraded, bool):
        return STATE_ERROR, False
    advisory = payload.get("advisory")
    flagged: Any = None
    if advisory is not None:
        if not isinstance(advisory, Mapping):
            return STATE_ERROR, False
        flagged = advisory.get("flagged")
        if not isinstance(flagged, bool):
            return STATE_ERROR, False
    risk = payload.get("canary_risk_score")
    if risk is not None and (not _finite_real(risk) or not 0.0 <= risk <= 1.0):
        return STATE_ERROR, False
    if safe and payload.get("blocked_by") is not None:
        return STATE_ERROR, False
    exercised = (
        degraded is False
        and payload.get("canary_status") == "exercised"
        and payload.get("analysis_status") == "exercised"
        and risk is not None
    )
    if not safe:
        return batch.STATE_BLOCK, exercised
    if degraded:
        return batch.STATE_DEGRADED, False
    if flagged:
        return batch.STATE_FLAG, exercised
    if payload.get("canary_status") != "exercised" or payload.get("analysis_status") != "exercised":
        return batch.STATE_UNEXERCISED, False
    if payload.get("analysis_method") == "llm_judge":
        return STATE_ERROR, False  # judge evidence has no sized context window; never a pass
    if risk is not None and risk > 0.0:
        # strict/v1: a measured non-zero risk is a detection signal even when the
        # analyzer raised no advisory; it is never a pass.
        return batch.STATE_FLAG, exercised
    return batch.STATE_PASS, exercised


def _signals(payload: Mapping[str, Any]) -> list[str]:
    out = []
    blocked_by = payload.get("blocked_by")
    if isinstance(blocked_by, str):
        out.append(blocked_by[:_MAX_SIGNAL_CHARS])
    advisory = payload.get("advisory")
    if isinstance(advisory, Mapping) and advisory.get("flagged") is True:
        raw = advisory.get("signals")
        if isinstance(raw, (list, tuple)):
            out.extend(s[:_MAX_SIGNAL_CHARS] for s in raw if isinstance(s, str))
    return out


def _pipeline_info(pipeline: Any, context_verified: bool) -> dict[str, Any]:
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
        "canary_num_ctx": _int_or_none(getattr(getattr(pipeline, "canary_probe", None), "num_ctx", None)),
        "canary_context_length": _int_or_none(getattr(getattr(pipeline, "canary_probe", None), "last_context_length", None)),
        "canary_context_verified": context_verified,
    }


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


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
    id_label = _valid_label(prepared.id)
    source_label = _valid_label(prepared.source)
    return RecordResult(
        index=prepared.index,
        id=None,
        source=None,
        length=len(text) if isinstance(text, str) else 0,
        sha256=sha256,
        material_sha256=material_sha256,
        metadata_keys=None,
        id_sha256=_sha256_text(id_label) if id_label is not None else None,
        source_sha256=_sha256_text(source_label) if source_label is not None else None,
        metadata_key_count=len(metadata_keys or []),
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
        if type(verdict) is not PipelineVerdict:  # a subclass could make to_dict() disagree with itself
            raise TypeError("pipeline.check returned a non-PipelineVerdict")
        # The verdict must be about exactly this segment: a cached or substituted
        # verdict for other text is evidence of nothing.
        if not _exact_str(verdict.input) or not str.__eq__(piece, verdict.input):
            raise ValueError("verdict input does not match the checked segment")
        snapshot = PipelineVerdict.to_dict(verdict)  # the class method, never an instance override
        if not isinstance(snapshot, dict):
            raise TypeError("verdict.to_dict() did not return a dict")
        # redacted at construction: the in-memory result never retains raw text
        payload = {k: v for k, v in snapshot.items() if k not in batch._RAW_TEXT_KEYS}
        # Every decision below reads the recorded snapshot, never the live object.
        state, exercised = _classify_payload(payload)
        if state == STATE_ERROR:
            raise ValueError("verdict is mistyped or self-contradictory")
        signals = _signals(payload)
        latency = float(payload.get("total_latency", 0.0))
        if not math.isfinite(latency):
            latency = 0.0
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

    covered = _covered_chars(segments)

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
        id=prepared.id if admitted else None,
        source=prepared.source if admitted else None,
        length=len(text),
        sha256=sha256,
        material_sha256=material_sha256,
        metadata_keys=sorted(metadata) if admitted else None,
        id_sha256=_sha256_text(prepared.id) if prepared.id is not None else None,
        source_sha256=_sha256_text(prepared.source) if prepared.source is not None else None,
        metadata_key_count=len(metadata),
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


#: Tokens reserved beyond the segment for the chat template and stop tokens.
CANARY_CONTEXT_RESERVE = 64


def required_canary_context(policy: IngestPolicy, pipeline: Any) -> int | None:
    """Context window (tokens) the Ollama canary needs to read a whole segment.

    Byte-level tokenizers never produce more tokens than UTF-8 bytes, and a
    character is at most 4 bytes, so ``4 * segment_chars`` bounds a segment's
    tokens; the system prompt is bounded the same way; ``max_tokens`` reserves
    the reply. Returns ``None`` when the pipeline has no Ollama ``CanaryProbe``
    (canary disabled, OpenAI-compatible provider, or a stand-in pipeline).
    """
    from .canary import CanaryProbe

    probe = getattr(pipeline, "canary_probe", None)
    if not isinstance(probe, CanaryProbe) or getattr(pipeline, "enable_canary", True) is False:
        return None
    system_prompt = getattr(probe, "system_prompt", "")
    prompt_bytes = 4 * len(system_prompt) if isinstance(system_prompt, str) else 0
    reply = probe.max_tokens if isinstance(probe.max_tokens, int) and not isinstance(probe.max_tokens, bool) else 0
    return 4 * policy.segment_chars + prompt_bytes + max(0, reply) + CANARY_CONTEXT_RESERVE


def _is_security_pipeline(pipeline: Any) -> bool:
    """A ``SecurityPipeline`` whose ``check`` is the library's own, so the gate's probe is the one checked."""
    return (
        isinstance(pipeline, SecurityPipeline)
        and type(pipeline).check is SecurityPipeline.check
        and "check" not in getattr(pipeline, "__dict__", {})
    )


def _check_canary_context(
    policy: IngestPolicy,
    pipeline: Any,
    verified: tuple[Any, ...] | None = None,
    *,
    unverified_pipeline: bool = False,
) -> tuple[Any, ...] | None:
    """Refuse before any check unless the canary can read every whole segment.

    Returns ``(probe, model, ollama_url, trained_context_length)`` for an Ollama
    canary so a later re-check of the same probe object, model and endpoint can
    reuse the trained length (``verified``) instead of querying ``/api/show``
    again; ``None`` otherwise.

    Only a ``SecurityPipeline`` (without an overridden ``check``) can be
    verified: for a wrapper or stand-in the gate cannot know which canary, if
    any, its ``check`` reaches. Any other pipeline is refused unless
    ``unverified_pipeline`` is set, and then the run records
    ``canary_context_verified: false`` (see ``ingest_records``).

    Ollama: ``num_ctx`` must be set and at least ``required_canary_context``, and
    the model's trained context length (``CanaryProbe.context_length()``, from
    ``/api/show``) must be at least as large, because Ollama caps ``num_ctx`` at
    the trained length and then silently truncates the prompt. An unreachable
    backend therefore refuses the run: coverage cannot be verified. The
    OpenAI-compatible provider offers no context control, and the LLM judge
    reads the whole segment without one, so neither is supported by ingest.
    """
    from .analyzer import BehavioralAnalyzer
    from .canary import CanaryProbe

    if not unverified_pipeline and not _is_security_pipeline(pipeline):
        raise ValueError(
            "ingest needs a SecurityPipeline: the canary context window of a wrapper or stand-in "
            "pipeline cannot be verified; pass unverified_pipeline=True to run it anyway "
            "(the manifest then records canary_context_verified false and verify_export refuses it)"
        )
    if getattr(pipeline, "enable_canary", True) is False:
        return None
    if getattr(pipeline, "use_judge", False) is True or (
        hasattr(pipeline, "analyzer") and type(pipeline.analyzer) is not BehavioralAnalyzer
    ):
        raise ValueError("ingest does not support judge_model: the LLM judge has no sized context window")
    if getattr(pipeline, "provider", None) == "openai" or (
        hasattr(pipeline, "canary_probe") and hasattr(pipeline, "provider")
        and type(pipeline.canary_probe) is not CanaryProbe
    ):
        raise ValueError(
            "ingest does not support provider='openai': the canary context window cannot be sized "
            "or verified there; use the Ollama provider"
        )
    needed = required_canary_context(policy, pipeline)
    if needed is None:
        return None
    probe = pipeline.canary_probe
    have = getattr(probe, "num_ctx", None)
    if not isinstance(have, int) or isinstance(have, bool) or have < needed:
        raise ValueError(
            f"the canary context window (num_ctx={have}) cannot hold a whole segment; "
            f"construct SecurityPipeline(canary_num_ctx={needed}) or larger, or lower segment_chars"
        )
    if (
        verified is not None
        and verified[0] is probe
        and verified[1] == getattr(probe, "model", None)
        and verified[2] == getattr(probe, "ollama_url", None)
    ):
        trained: int | None = verified[3]
    else:
        trained = probe.context_length()
    if trained is None:
        raise ValueError(
            "could not verify the canary model's context length (backend unreachable or "
            "model unknown); ingest refuses to run without it"
        )
    if trained < needed:
        raise ValueError(
            f"the canary model's trained context length ({trained}) is smaller than the "
            f"{needed} tokens a whole segment may need; lower segment_chars or use a larger-context model"
        )
    return (probe, getattr(probe, "model", None), getattr(probe, "ollama_url", None), trained)


def ingest_records(
    pipeline: Any,
    records: Iterable[Any],
    *,
    policy: IngestPolicy | None = None,
    now: Callable[[], datetime] | None = None,
    unverified_pipeline: bool = False,
) -> IngestResult:
    """Screen every record's material and decide admission under ``policy``.

    All records are read, snapshotted and budgeted before any check runs.
    Run-level ``ValueError`` (nothing checked, nothing returned): invalid policy,
    ``segment_chars`` above the pipeline's structural ``max_input_length``, a
    pipeline that is not a ``SecurityPipeline`` (unless ``unverified_pipeline``),
    an Ollama canary whose ``num_ctx`` is unset or smaller than
    ``required_canary_context`` (the backend would silently truncate a long
    segment and the manifest would still call it exercised), more
    than ``max_items`` records, summed text bytes above ``max_total_bytes``, or a
    record that is not a string/object/IngestRecord/BatchItem. Record-level
    problems are held records, never run failures. ``KeyboardInterrupt`` and other
    ``BaseException`` propagate, so no partial result exists.

    ``unverified_pipeline=True`` (tests, stand-ins, the eval's ``--offline-fake``)
    runs a wrapper or stand-in pipeline whose canary context cannot be verified.
    Records are still screened and admitted in memory, but the manifest records
    ``pipeline.canary_context_verified: false`` and ``verify_export`` refuses
    every such pair. ``canary_context_verified`` is ``true`` only for a
    ``SecurityPipeline`` whose Ollama canary passed the context gate.
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
    verified = _check_canary_context(policy, pipeline, unverified_pipeline=unverified_pipeline)
    clock =now if now is not None else (lambda: datetime.now(timezone.utc))

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
    # Reading the records (and the caller's clock) may have run caller code;
    # re-verify the pipeline right before the first check so a mid-read change
    # cannot bypass the gate.
    rechecked = _check_canary_context(policy, pipeline, verified, unverified_pipeline=unverified_pipeline)
    context_verified = rechecked is not None and _is_security_pipeline(pipeline)
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
        metadata: dict[str, str] = item.metadata if item.metadata is not None else {}  # the phase-1 copy
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
        pipeline_info=_pipeline_info(pipeline, context_verified),
        started_at=started_at,
        finished_at=_iso_utc(clock()),
        checks_performed=counter.calls,
        status=STATUS_COMPLETE,
    )


# ---------------------------------------------------------------------------
# Atomic writers
# ---------------------------------------------------------------------------


def _write_temp(target: str, data: bytes, register: list[str] | None = None) -> str:
    """Write ``data`` to a fsynced temp file next to ``target``; return the temp path.

    When ``register`` is given the temp path is appended to it right after
    creation, so a caller's cleanup sees it even if this function is interrupted.
    """
    directory = os.path.dirname(os.path.abspath(target))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(target) + ".", suffix=".tmp")
    if register is not None:
        register.append(tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return tmp


def _publish_temp(tmp: str, target: str, *, overwrite: bool) -> None:
    """Atomically move a temp file onto ``target``; the temp file is always removed."""
    try:
        if overwrite:
            os.replace(tmp, target)
        else:
            # Atomic no-clobber publish: link() fails if the target appeared since the
            # existence check, so a racing writer is never overwritten.
            try:
                os.link(tmp, target)
            except FileExistsError:
                raise FileExistsError(f"refusing to overwrite existing file: {target}") from None
            except OSError:
                # Filesystem without hard links: best-effort re-check, then rename.
                if os.path.lexists(target):
                    raise FileExistsError(f"refusing to overwrite existing file: {target}") from None
                os.replace(tmp, target)
    finally:
        # The temp file is a complete copy of the document; remove it, retrying once
        # on a transient error so a hidden duplicate is not left beside the target.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
    directory = os.path.dirname(os.path.abspath(target))
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
            with contextlib.suppress(OSError):
                os.close(dir_fd)


def _atomic_write(path: str | os.PathLike[str], data: bytes, *, overwrite: bool) -> str:
    target = os.fspath(path)
    if not overwrite and os.path.lexists(target):
        raise FileExistsError(f"refusing to overwrite existing file: {target}")
    _publish_temp(_write_temp(target, data), target, overwrite=overwrite)
    return hashlib.sha256(data).hexdigest()


def publish(
    result: IngestResult,
    manifest_path: str | os.PathLike[str],
    export_path: str | os.PathLike[str] | None = None,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Write the manifest and (optionally) the export as one publication.

    Both documents are fully written to temp files before either target is
    touched; the export is published first, then the manifest, so a valid
    manifest on disk implies its export was already there. With ``overwrite``
    the previous files are removed before anything is written. If any step
    fails, every temp file is removed and an export published in this call is
    unlinked again, leaving no artefact of this call behind (an empty temp file
    created in the instant before it is registered can remain). Returns ``{"manifest": sha256,
    "export": sha256}`` (``export`` only when requested). Marks
    ``result.export_requested`` so the manifest records the request.
    """
    if result.status != STATUS_COMPLETE:
        raise ValueError("export requires a complete ingest run")
    manifest_target = os.fspath(manifest_path)
    export_target = os.fspath(export_path) if export_path is not None else None
    result.export_requested = export_target is not None
    if export_target is not None and _same_file(manifest_target, export_target):
        raise ValueError("manifest and export paths must be different files")
    for target in (manifest_target, export_target):
        if target is None or not os.path.lexists(target):
            continue
        if not overwrite:
            raise FileExistsError(f"refusing to overwrite existing file: {target}")
        # Consent to overwrite means the previous pair is removed before anything is
        # written, so a failure part-way can never leave a stale or mixed pair behind.
        os.unlink(target)
    manifest_data = result.manifest_json().encode("utf-8")
    export_data = _canonical_json(result.export_document()).encode("utf-8") if export_target else None
    digests = {"manifest": hashlib.sha256(manifest_data).hexdigest()}
    if export_data is not None:
        digests["export"] = hashlib.sha256(export_data).hexdigest()

    temps: list[str] = []
    published: list[str] = []  # targets this call may have created, most recent last
    try:
        manifest_tmp = _write_temp(manifest_target, manifest_data, temps)
        if export_target is not None and export_data is not None:
            export_tmp = _write_temp(export_target, export_data, temps)
            published.append(export_target)  # counted as ours from the moment publish is attempted
            try:
                _publish_temp(export_tmp, export_target, overwrite=overwrite)
            except FileExistsError:
                published.remove(export_target)  # a racing writer's file: not ours, never removed
                raise
            temps.remove(export_tmp)
        published.append(manifest_target)
        try:
            _publish_temp(manifest_tmp, manifest_target, overwrite=overwrite)
        except FileExistsError:
            published.remove(manifest_target)
            raise
        temps.remove(manifest_tmp)
    except BaseException:
        # Roll back everything this call touched: temp files and any target it
        # published (or may have published) before the failure.
        for tmp in temps:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        for target in reversed(published):
            with contextlib.suppress(OSError):
                os.unlink(target)
        raise
    return digests


def _same_file(a: str, b: str) -> bool:
    if os.path.abspath(a) == os.path.abspath(b) or os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


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


_EXPORT_KEYS = frozenset({"schema", "manifest_schema", "manifest_sha256", "policy_name", "records"})


def verify_export(
    export_doc: Any, manifest: Any, *, manifest_bytes: bytes | None = None
) -> list[str]:
    """Return every inconsistency between an export and its manifest ([] = consistent).

    Checks schemas and the exact export field set, the manifest hash binding
    (over the canonical manifest and, when ``manifest_bytes`` is given, over the
    raw file bytes too), that every exported record is admitted in the manifest
    with complete coverage and no detection, that the exported sequence equals
    the admitted sequence in manifest order, that manifest indices are unique and
    match ``run.records_total``, that ``pipeline.canary_context_verified`` is
    ``true`` (a run with an unverified pipeline is always refused, even when it
    exports nothing), and that ``sha256``/``material_sha256``
    recomputed from the exported text and metadata match. Problems name record
    indices only, never text.
    """
    problems: list[str] = []
    if not isinstance(export_doc, dict):
        return ["export is not an object"]
    if not isinstance(manifest, dict):
        return ["manifest is not an object"]
    if set(export_doc) != _EXPORT_KEYS:
        problems.append("export has unexpected or missing top-level fields")
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
    if manifest_bytes is not None and (
        not isinstance(manifest_bytes, (bytes, bytearray))
        or hashlib.sha256(bytes(manifest_bytes)).hexdigest() != export_doc.get("manifest_sha256")
    ):
        problems.append("manifest_sha256 does not match the manifest file bytes")
    policy = manifest.get("policy")
    if export_doc.get("policy_name") != POLICY_NAME or not (
        isinstance(policy, dict) and policy.get("name") == export_doc.get("policy_name")
    ):
        problems.append("policy name mismatch")
    run = manifest.get("run")
    if not (isinstance(run, dict) and run.get("status") == STATUS_COMPLETE):
        problems.append("manifest run is not complete")
    if isinstance(run, dict) and run.get("export_requested") is not True:
        problems.append("manifest does not record that an export was requested")
    pipeline_info = manifest.get("pipeline")
    if not (isinstance(pipeline_info, dict) and pipeline_info.get("canary_context_verified") is True):
        problems.append("manifest does not record a verified canary context window")

    by_index: dict[int, dict[str, Any]] = {}
    manifest_records = manifest.get("records")
    if not isinstance(manifest_records, list):
        problems.append("manifest records missing")
        manifest_records = []
    admitted_order: list[int] = []
    for pos, rec in enumerate(manifest_records):
        if not (isinstance(rec, dict) and _is_int(rec.get("index"))):
            problems.append(f"manifest record at position {pos}: malformed")
            continue
        if rec["index"] in by_index or rec["index"] != pos:
            problems.append(f"manifest record at position {pos}: duplicate or out-of-order index")
        by_index[rec["index"]] = rec
        if rec.get("admission") == ADMISSION_ADMITTED:
            admitted_order.append(rec["index"])
    admitted_indices = set(admitted_order)
    if not (isinstance(run, dict) and run.get("records_total") == len(manifest_records)):
        problems.append("manifest records_total does not match the record list")

    export_records = export_doc.get("records")
    if not isinstance(export_records, list):
        problems.append("export records missing")
        return problems
    seen: set[int] = set()
    order: list[int] = []
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
        order.append(idx)
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
        if not _segment_evidence_supports_admission(mrec):
            problems.append(f"{label}: segment evidence does not support admission")
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
        for name in ("id", "source"):
            value = rec.get(name)
            if not (value is None or _exact_str(value)) or not (mrec.get(name) is None or _exact_str(mrec.get(name))):
                problems.append(f"{label}: {name} must be a string or null")
                continue
            expected = _sha256_text(value) if isinstance(value, str) else None
            if mrec.get(f"{name}_sha256") != expected:
                problems.append(f"{label}: {name} digest mismatch")
        if sorted(metadata) != mrec.get("metadata_keys") or mrec.get("metadata_key_count") != len(metadata):
            problems.append(f"{label}: metadata keys mismatch")
        if not _segments_match_material(mrec, manifest.get("policy"), rec.get("id"), rec.get("source"), metadata, text):
            problems.append(f"{label}: segment evidence does not cover the exported material")
    missing = admitted_indices - seen
    if missing:
        problems.append(f"admitted records missing from export: {sorted(missing)}")
    if order != admitted_order and not missing and seen <= admitted_indices:
        problems.append("export records are not in manifest order")
    counts = manifest.get("counts")
    if not (isinstance(counts, dict) and counts.get("admitted") == len(export_records)):
        problems.append("export record count does not match manifest admitted count")
    if isinstance(counts, dict) and counts != _recount(manifest_records):
        problems.append("manifest counts do not match its records")
    return problems


def _recount(records: list[Any]) -> dict[str, Any]:
    by_reason = dict.fromkeys(HOLD_REASONS, 0)
    detection = dict.fromkeys(DETECTION_STATES, 0)
    coverage = dict.fromkeys(COVERAGE_STATES, 0)
    admitted = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if rec.get("admission") == ADMISSION_ADMITTED:
            admitted += 1
        reasons = rec.get("hold_reasons")
        for reason in reasons if isinstance(reasons, list) else []:
            if isinstance(reason, str) and reason in by_reason:
                by_reason[reason] += 1
        if isinstance(rec.get("detection"), str) and rec["detection"] in detection:
            detection[rec["detection"]] += 1
        if isinstance(rec.get("coverage"), str) and rec["coverage"] in coverage:
            coverage[rec["coverage"]] += 1
    return {
        "admitted": admitted,
        "held": len(records) - admitted,
        "by_reason": by_reason,
        "detection": detection,
        "coverage": coverage,
    }


def _segments_match_material(
    mrec: dict[str, Any], policy: Any, id_: Any, source: Any, metadata: dict[str, str], text: str
) -> bool:
    """The manifest's segments are exactly the policy's plan over the exported material.

    Rebuilds the metadata material and both segment plans from the exported record
    and the manifest policy, then requires kind/index/start/end to match the plan,
    each segment ``sha256`` to equal the hash of its slice, and ``chars_total`` to
    equal text plus metadata material length. Otherwise the manifest could claim
    coverage of material that was never checked.
    """
    if not isinstance(policy, dict):
        return False
    seg_chars, overlap = policy.get("segment_chars"), policy.get("segment_overlap")
    if not isinstance(seg_chars, int) or not isinstance(overlap, int) or isinstance(seg_chars, bool) or isinstance(overlap, bool):
        return False
    if seg_chars < 1 or not 0 <= overlap < seg_chars:
        return False
    meta_text = "\n".join(_metadata_lines(id_ if isinstance(id_, str) else None,
                                          source if isinstance(source, str) else None, metadata))
    try:
        plan = [(SEGMENT_METADATA, i, s, e, meta_text) for i, (s, e) in enumerate(
            segment_text(meta_text, seg_chars, overlap) if meta_text else [])]
        plan += [(SEGMENT_TEXT, i, s, e, text) for i, (s, e) in enumerate(segment_text(text, seg_chars, overlap))]
    except (ValueError, OverflowError, TypeError, MemoryError):
        return False
    segments = mrec.get("segments")
    if not isinstance(segments, list) or len(segments) != len(plan):
        return False
    if mrec.get("chars_total") != len(text) + len(meta_text):
        return False
    for seg, (kind, index, start, end, material) in zip(segments, plan):
        if not isinstance(seg, dict):
            return False
        if seg.get("kind") != kind or seg.get("index") != index or seg.get("start") != start or seg.get("end") != end:
            return False
        if seg.get("sha256") != _sha256_text(material[start:end]):
            return False
    return True


def _segment_evidence_supports_admission(mrec: dict[str, Any]) -> bool:
    """Every planned segment recorded as an exercised pass, with full accounting."""
    segments = mrec.get("segments")
    total = mrec.get("segments_total")
    if not isinstance(segments, list) or not segments or not _is_int(total) or total != len(segments):
        return False
    if mrec.get("segments_checked") != total:
        return False
    chars_total = mrec.get("chars_total")
    if not isinstance(chars_total, int) or isinstance(chars_total, bool):
        return False
    if mrec.get("chars_covered") != chars_total or chars_total < 1:
        return False
    for seg in segments:
        if not isinstance(seg, dict):
            return False
        if seg.get("state") != batch.STATE_PASS or seg.get("exercised") is not True:
            return False
        verdict = seg.get("verdict")
        if not isinstance(verdict, dict):
            return False
        state, exercised = _classify_payload(verdict)
        if state != batch.STATE_PASS or not exercised:
            return False
    return True
