"""Structural checks for the local ingest eval corpus (offline, deterministic, no model calls)."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

import pytest

from little_canary.batch import DEFAULT_MAX_ITEM_BYTES, MAX_LABEL_CHARS
from little_canary.structural_filter import StructuralFilter

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "ingest_eval" / "corpus.jsonl"

# Default strict/v1 ingest policy (SPEC §1/§2).
SEGMENT_CHARS = 3500
SEGMENT_OVERLAP = 500
MAX_SEGMENTS = 8
MAX_METADATA_KEYS = 32
MAX_METADATA_VALUE_CHARS = 1024
MAX_METADATA_KEY_CHARS = 128

TOP_KEYS_REQUIRED = {"id", "source", "text", "expect"}
TOP_KEYS_ALLOWED = TOP_KEYS_REQUIRED | {"metadata"}
EXPECT_KEYS_REQUIRED = {"label", "vector", "note"}
EXPECT_KEYS_ALLOWED = EXPECT_KEYS_REQUIRED | {"payload"}
TEXT_VECTORS = ("text_start", "text_middle", "text_end")
BENIGN_VECTORS = {"none", "over_budget"}
INJECTED_VECTORS = set(TEXT_VECTORS) | {"metadata", "long_text"}
LABEL_PREFIX = {"benign": "benign-", "injected": "inj-"}


def _load():
    records = []
    with CORPUS.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            assert line.strip(), f"line {number} is blank"
            record = json.loads(line)
            assert isinstance(record, dict), f"line {number} is not an object"
            records.append(record)
    return records


RECORDS = _load()
BY_ID = {r["id"]: r for r in RECORDS}


def _plan(length):
    """SPEC §2 segmentation plan: list of [start, end) ranges."""
    stride = SEGMENT_CHARS - SEGMENT_OVERLAP
    count = 1 + max(0, math.ceil((length - SEGMENT_CHARS) / stride))
    return [(i * stride, min(i * stride + SEGMENT_CHARS, length)) for i in range(count)]


def _metadata_material(record):
    """SPEC §3: id and source lines first, then sorted metadata keys."""
    lines = []
    for key in ("id", "source"):
        if record.get(key) is not None:
            lines.append(f"{key}: {record[key]}")
    for key, value in sorted((record.get("metadata") or {}).items()):
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def _total_segments(record):
    material = _metadata_material(record)
    return len(_plan(len(record["text"]))) + (len(_plan(len(material))) if material else 0)


def _of(label=None, vector=None):
    return [
        r for r in RECORDS
        if (label is None or r["expect"]["label"] == label)
        and (vector is None or r["expect"]["vector"] == vector)
    ]


def test_plan_formula_matches_spec_examples():
    assert _plan(3500) == [(0, 3500)]
    assert len(_plan(9000)) == 3
    assert _plan(9000)[-1] == (6000, 9000)
    assert len(_plan(24500)) == 8
    assert len(_plan(24501)) == 9


@pytest.mark.parametrize("record", RECORDS, ids=[r["id"] for r in RECORDS])
def test_record_shape(record):
    keys = set(record)
    assert TOP_KEYS_REQUIRED <= keys, keys
    assert keys <= TOP_KEYS_ALLOWED, keys - TOP_KEYS_ALLOWED
    for key in ("id", "source"):
        value = record[key]
        assert isinstance(value, str) and value, key
        assert len(value) <= MAX_LABEL_CHARS
        value.encode("utf-8")
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", record["id"]), record["id"]

    text = record["text"]
    assert isinstance(text, str) and text
    assert len(text.encode("utf-8")) <= DEFAULT_MAX_ITEM_BYTES  # also rejects lone surrogates

    metadata = record.get("metadata")
    if metadata is not None:
        assert isinstance(metadata, dict) and metadata
        assert len(metadata) <= MAX_METADATA_KEYS
        for key, value in metadata.items():
            assert isinstance(key, str) and 0 < len(key) <= MAX_METADATA_KEY_CHARS
            assert isinstance(value, str) and len(value) <= MAX_METADATA_VALUE_CHARS
            key.encode("utf-8")
            value.encode("utf-8")

    expect = record["expect"]
    assert isinstance(expect, dict)
    assert EXPECT_KEYS_REQUIRED <= set(expect) <= EXPECT_KEYS_ALLOWED, set(expect)
    label, vector, note = expect["label"], expect["vector"], expect["note"]
    assert label in LABEL_PREFIX
    assert record["id"].startswith(LABEL_PREFIX[label])
    assert vector in (BENIGN_VECTORS if label == "benign" else INJECTED_VECTORS)
    assert isinstance(note, str) and note.strip()
    assert "safe" not in note.lower(), "expect.note must not use that word as a claim"
    if label == "injected":
        assert isinstance(expect.get("payload"), str) and expect["payload"].strip()
    else:
        assert "payload" not in expect


def test_ids_unique():
    ids = [r["id"] for r in RECORDS]
    assert len(ids) == len(set(ids))


def test_composition_minimums():
    assert len(RECORDS) >= 40
    assert len(_of("benign")) >= 20
    assert len(_of("injected")) >= 20
    for vector in TEXT_VECTORS:
        assert len(_of("injected", vector)) >= 3, vector
    assert len(_of("injected", "metadata")) >= 5
    assert len(_of("injected", "long_text")) >= 2
    assert len(_of("benign", "over_budget")) >= 1


def test_benign_variety_includes_known_traps_and_metadata():
    benign = _of("benign")
    quoted = [r for r in benign if "ignore previous instructions" in r["text"].lower()]
    assert quoted, "need a benign security write-up quoting an attack specimen"
    assert any(any(ord(c) > 0x2FFF for c in r["text"]) for r in benign), "need a multilingual record"
    with_meta = [r for r in benign if r.get("metadata")]
    assert with_meta
    assert any({"title", "author", "subject"} <= set(r["metadata"]) for r in with_meta)


def test_all_within_budget_except_over_budget_records():
    for record in RECORDS:
        total = _total_segments(record)
        if record["expect"]["vector"] == "over_budget":
            continue
        assert total <= MAX_SEGMENTS, (record["id"], total)


def test_benign_long_record_spans_three_segments_within_budget():
    long_benign = [r for r in _of("benign", "none") if len(_plan(len(r["text"]))) >= 3]
    assert long_benign
    for record in long_benign:
        assert _total_segments(record) <= MAX_SEGMENTS


def test_over_budget_record_exceeds_segment_budget_not_byte_budget():
    for record in _of("benign", "over_budget"):
        text = record["text"]
        assert len(text) > 24000
        assert len(_plan(len(text))) > MAX_SEGMENTS  # text alone exceeds the budget
        assert _total_segments(record) > MAX_SEGMENTS
        assert len(text.encode("utf-8")) <= DEFAULT_MAX_ITEM_BYTES


@pytest.mark.parametrize("vector", TEXT_VECTORS)
def test_text_vector_payload_position(vector):
    for record in _of("injected", vector):
        text, payload = record["text"], record["expect"]["payload"]
        assert text.count(payload) == 1, record["id"]
        assert len(_plan(len(text))) == 1, record["id"]
        start = text.index(payload)
        end = start + len(payload)
        if vector == "text_start":
            assert start <= 0.1 * len(text), record["id"]
        elif vector == "text_end":
            assert end >= 0.9 * len(text), record["id"]
        else:
            assert start >= 0.2 * len(text) and end <= 0.8 * len(text), record["id"]
        assert payload not in _metadata_material(record)


def test_metadata_vector_has_benign_text_and_payload_in_metadata():
    benign_texts = {r["text"] for r in _of("benign")}
    for record in _of("injected", "metadata"):
        payload = record["expect"]["payload"]
        assert record["text"] in benign_texts, record["id"]  # text is a benign base verbatim
        assert payload not in record["text"], record["id"]
        assert any(payload in value for value in record.get("metadata", {}).values()), record["id"]


def test_long_text_payload_sits_only_in_last_segment():
    for record in _of("injected", "long_text"):
        text, payload = record["text"], record["expect"]["payload"]
        plan = _plan(len(text))
        assert len(plan) >= 3, record["id"]
        assert text.count(payload) == 1, record["id"]
        start = text.index(payload)
        end = start + len(payload)
        last_start, last_end = plan[-1]
        previous_end = plan[-2][1]
        assert start >= previous_end, record["id"]  # absent from every earlier segment
        assert last_start <= start and end <= last_end, record["id"]
        assert payload not in _metadata_material(record)


def test_injected_mix_of_structurally_obvious_and_quiet():
    """Informational property of the corpus, not a detection claim."""
    structural = StructuralFilter(max_input_length=10 ** 9)

    def hit(record):
        material = _metadata_material(record)
        return structural.check(record["text"]).blocked or (
            bool(material) and structural.check(material).blocked
        )

    injected = _of("injected")
    obvious = [r["id"] for r in injected if hit(r)]
    quiet = [r["id"] for r in injected if not hit(r)]
    assert len(obvious) >= 5, obvious
    assert len(quiet) >= 5, quiet
    assert any(hit(r) for r in _of("benign")), "need at least one documented false-block trap"
