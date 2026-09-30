"""examples/ingest_consumer.py: held, tampered or unassessed records never reach downstream."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from little_canary import (
    IngestPolicy,
    ingest_records,
    publish,
    verify_export,
    write_export,
    write_manifest,
)
from little_canary.ingest import EXPORT_SCHEMA, MANIFEST_SCHEMA, POLICY_NAME
from little_canary.pipeline import PipelineVerdict, SecurityAdvisory

ROOT = Path(__file__).resolve().parent.parent
CONSUMER_PATH = ROOT / "examples" / "ingest_consumer.py"

_spec = importlib.util.spec_from_file_location("ingest_consumer_example", CONSUMER_PATH)
consumer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(consumer)

SENTINEL = "SENTINEL-c0nsum3r-do-not-leak"


# -- FakePipeline (copied in miniature from tests/test_ingest.py) -------------

def _verdict(text, **kw):
    base = dict(safe=True, input=text, safe_input=text, total_latency=0.0,
                canary_status="exercised", analysis_status="exercised",
                canary_risk_score=0.0)
    base.update(kw)
    return PipelineVerdict(**base)


class FakePipeline:
    """Deterministic stand-in: exercised pass unless the segment text says otherwise."""

    def check(self, text):
        if "BLOCK" in text:
            return _verdict(text, safe=False, blocked_by="canary", canary_risk_score=0.9)
        if "FLAG" in text:
            return _verdict(text, canary_risk_score=0.4, advisory=SecurityAdvisory(
                flagged=True, severity="medium", signals=["sig_x"], message="m"))
        if "DEGRADE" in text:
            return _verdict(text, degraded=True, canary_status="failed", canary_risk_score=None)
        if "NORISK" in text:
            return _verdict(text, canary_risk_score=None)
        return _verdict(text)


def _clock():
    return datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


POLICY = IngestPolicy(segment_chars=40, segment_overlap=5, max_segments=5)

RECORDS = [
    {"text": "alpha\r\n  " + SENTINEL + "  \t", "id": "id-" + SENTINEL, "source": "src",
     "metadata": {"title": "T " + SENTINEL, "author": "a"}},        # 0 admitted (metadata too)
    "please BLOCK " + SENTINEL,                                       # 1 blocked
    "FLAG " + SENTINEL,                                               # 2 flagged
    "DEGRADE " + SENTINEL,                                            # 3 degraded
    "y" * 200 + SENTINEL,                                             # 4 over budget
    {"text": ""},                                                     # 5 malformed
    "héllo wörld ✓ ​ \U0001f600 " + SENTINEL,  # 6 admitted, 2 segments
    {"text": "fine " + SENTINEL, "extra": "x"},                       # 7 malformed (unknown key)
    "NORISK " + SENTINEL,                                             # 8 incomplete
    "plain admitted record",                                          # 9 admitted
    {"text": "benign body", "metadata": {"subject": "FLAG " + SENTINEL}},  # 10 flagged via metadata
]
ADMITTED = [0, 6, 9]


def _text(i):
    rec = RECORDS[i]
    return rec["text"] if isinstance(rec, dict) else rec


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _material(rec):
    doc = {"id": rec["id"], "source": rec["source"],
           "metadata": dict(sorted(rec["metadata"].items())), "text": rec["text"]}
    return _sha(json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")))


def _run(records=RECORDS):
    return ingest_records(FakePipeline(), records, policy=POLICY, now=_clock)


@pytest.fixture
def pair(tmp_path):
    result = _run()
    mpath, epath = tmp_path / "manifest.json", tmp_path / "admitted.json"
    publish(result, mpath, epath)  # export first, then the manifest that records the request
    return mpath, epath


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _dump(path, doc):
    Path(path).write_text(json.dumps(doc), encoding="utf-8")


def _held_export_record(i, text):
    rec = {"index": i, "id": None, "source": None, "metadata": {}, "text": text}
    rec["sha256"] = _sha(text)
    rec["material_sha256"] = _material(rec)
    return rec


def _refused(mpath, epath):
    got = []
    with pytest.raises(consumer.Refused) as info:
        consumer.consume(str(mpath), str(epath), got.append)
    assert got == []  # all-or-nothing: downstream received nothing
    return info.value.problems


# (1) valid pair --------------------------------------------------------------

def test_fixture_mixes_every_outcome():
    reasons = {tuple(r.hold_reasons) for r in _run().records}
    assert [r.index for r in _run().records if r.admission == "admitted"] == ADMITTED
    for reason in ("blocked", "flagged", "degraded", "over_budget", "malformed", "incomplete"):
        assert any(reason in rs for rs in reasons)


def test_valid_pair_consumes_exactly_the_admitted_records_once(pair):
    got = []
    consumed = consumer.consume(str(pair[0]), str(pair[1]), got.append)
    assert consumed == ADMITTED
    assert [r["index"] for r in got] == ADMITTED  # each once
    for rec in got:
        assert rec["text"].encode("utf-8") == _text(rec["index"]).encode("utf-8")  # byte-identical


# (2) held record inserted ----------------------------------------------------

@pytest.mark.parametrize("keep_count", [False, True], ids=["appended", "swapped-for-admitted"])
def test_held_record_inserted_into_export_is_refused(pair, keep_count):
    mpath, epath = pair
    export = _load(epath)
    # held index 1 with its exact original text: sha256 even matches the manifest entry
    held = _held_export_record(1, _text(1))
    assert held["sha256"] == _load(mpath)["records"][1]["sha256"]
    if keep_count:
        export["records"][-1] = held
    else:
        export["records"].append(held)
    _dump(epath, export)
    assert "record 1: not admitted in manifest" in _refused(mpath, epath)


def test_consumer_does_not_rely_on_verify_export_alone(pair, monkeypatch):
    """Even if verify_export reported nothing, the consumer's own checks refuse."""
    monkeypatch.setattr(consumer, "verify_export", lambda export, manifest, **kw: [])
    mpath, epath = pair
    export = _load(epath)
    export["records"].append(_held_export_record(1, _text(1)))
    _dump(epath, export)
    assert "record 1: not admitted in manifest" in _refused(mpath, epath)

    export = _load(epath)
    export["records"] = export["records"][:3]
    export["records"][2]["text"] += "!"
    _dump(epath, export)
    problems = _refused(mpath, epath)
    assert "record 9: sha256 does not match the text" in problems
    assert "record 9: material_sha256 does not match" in problems

    _dump(epath, {"records": [{"index": "x"}]})
    assert _refused(mpath, epath) == ["export or manifest structure invalid"]


# (3) tampered text -----------------------------------------------------------

@pytest.mark.parametrize("rehash", [False, True], ids=["stale-hash", "rehashed"])
def test_one_char_tamper_refuses_everything(pair, rehash):
    mpath, epath = pair
    export = _load(epath)
    rec = export["records"][2]  # index 9; 0 and 6 stay untouched
    rec["text"] = "Plain admitted record"
    if rehash:
        rec["sha256"] = _sha(rec["text"])
        rec["material_sha256"] = _material(rec)
    _dump(epath, export)
    problems = _refused(mpath, epath)
    assert "record 9: sha256 mismatch" in problems


# (4) manifest from another run -------------------------------------------------

def test_manifest_from_a_different_run_is_refused(pair, tmp_path):
    other = tmp_path / "other-manifest.json"
    write_manifest(_run(RECORDS[:-1]), other)
    problems = _refused(other, pair[1])
    assert "manifest_sha256 does not match the manifest" in problems


# (5) manifest flipped to admitted --------------------------------------------

@pytest.mark.parametrize("export_it", [False, True], ids=["manifest-only", "also-exported"])
def test_manifest_flip_to_admitted_without_rehash_is_refused(pair, export_it):
    mpath, epath = pair
    manifest = _load(mpath)
    flipped = manifest["records"][1]
    flipped.update(admission="admitted", hold_reasons=[], coverage="complete", detection="none")
    manifest["counts"]["admitted"] += 1
    _dump(mpath, manifest)
    if export_it:
        export = _load(epath)
        export["records"].append(_held_export_record(1, _text(1)))
        _dump(epath, export)
    assert "manifest_sha256 does not match the manifest" in _refused(mpath, epath)


# (6) extra key / duplicate index ---------------------------------------------

def test_export_record_with_unknown_key_is_refused(pair):
    mpath, epath = pair
    export = _load(epath)
    export["records"][0]["instructions"] = "unscreened"
    _dump(epath, export)
    assert "record 0: unexpected or missing fields" in _refused(mpath, epath)


def test_export_with_duplicate_index_is_refused(pair):
    mpath, epath = pair
    export = _load(epath)
    export["records"].append(copy.deepcopy(export["records"][0]))
    _dump(epath, export)
    assert "record 0: duplicated in export" in _refused(mpath, epath)


def test_verify_export_rejects_unknown_top_level_export_key():
    result = _run()
    export = result.export_document()
    export["notes"] = "unscreened text a careless consumer might forward"
    assert verify_export(export, result.manifest()) != []


# (7) missing / unreadable ------------------------------------------------------

@pytest.mark.parametrize("which,content", [
    ("manifest", None), ("export", None),
    ("manifest", b"{not json " + SENTINEL.encode()),
    ("export", b"\xff\xfe" + SENTINEL.encode()),
])
def test_missing_or_unreadable_file_refused_exit_2(pair, capsys, which, content):
    mpath, epath = pair
    target = mpath if which == "manifest" else epath
    if content is None:
        os.unlink(target)
    else:
        target.write_bytes(content)
    problems = _refused(mpath, epath)
    assert len(problems) == 1 and problems[0].startswith(f"cannot read {which}")
    assert consumer.main(["--manifest", str(mpath), "--export", str(epath)]) == 2
    assert SENTINEL not in "".join(capsys.readouterr())


def test_directory_path_refused_exit_2(pair, tmp_path):
    assert consumer.main(["--manifest", str(tmp_path), "--export", str(pair[1])]) == 2


# (8) main exit codes + (9) no text in output -----------------------------------

def test_main_exit_0_lists_consumed_and_held_without_text(pair, capsys):
    assert consumer.main(["--manifest", str(pair[0]), "--export", str(pair[1])]) == 0
    out, err = capsys.readouterr()
    assert "consumed indices (verified against the manifest): [0, 6, 9]" in out
    assert "held record 1: blocked" in out
    assert "held record 5: malformed" in out
    assert SENTINEL not in out + err
    assert "safe" not in (out + err).lower()


def test_main_exit_2_on_refusal_without_text(pair, capsys):
    mpath, epath = pair
    export = _load(epath)
    export["records"][0]["text"] = export["records"][0]["text"].replace("alpha", "alphA")
    export["records"].append(_held_export_record(2, _text(2)))
    _dump(epath, export)
    assert consumer.main(["--manifest", str(mpath), "--export", str(epath)]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "REFUSED: nothing consumed" in err
    assert SENTINEL not in out + err


def test_main_requires_both_paths():
    with pytest.raises(SystemExit) as info:
        consumer.main(["--manifest", "m.json"])
    assert info.value.code == 2


def test_cli_smoke_subprocess(pair):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    cmd = [sys.executable, str(CONSUMER_PATH), "--manifest", str(pair[0]), "--export", str(pair[1])]
    ok = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert ok.returncode == 0, ok.stderr
    assert "[0, 6, 9]" in ok.stdout
    pair[1].write_text(pair[1].read_text(encoding="utf-8").replace("plain", "plaiN"), encoding="utf-8")
    bad = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert bad.returncode == 2
    assert "nothing consumed" in bad.stderr
    assert SENTINEL not in ok.stdout + ok.stderr + bad.stdout + bad.stderr


# (10) --expect-manifest-sha256 / consistency-vs-authenticity warning ----------

def _msha(mpath):
    return hashlib.sha256(Path(mpath).read_bytes()).hexdigest()


def _main(mpath, epath, *extra):
    return consumer.main(["--manifest", str(mpath), "--export", str(epath), *extra])


@pytest.mark.parametrize("fmt", [str, str.upper, lambda h: f"  {h}\n"], ids=["lower", "upper", "padded"])
def test_expected_manifest_sha256_match_consumes_without_warning(pair, capsys, fmt):
    """Semantic I: --expect-manifest-sha256 equal to the manifest file's sha256 (case/whitespace
    insensitive) consumes the pair and prints no consistency-only warning."""
    assert _main(*pair, "--expect-manifest-sha256", fmt(_msha(pair[0]))) == 0
    out, err = capsys.readouterr()
    assert "consumed indices (verified against the manifest): [0, 6, 9]" in out
    assert "WARNING" not in err
    assert SENTINEL not in out + err


def test_expected_manifest_sha256_mismatch_refused_exit_2(pair, capsys):
    """Semantic I: --expect-manifest-sha256 that differs from the manifest bytes => exit 2, nothing consumed."""
    assert _main(*pair, "--expect-manifest-sha256", "0" * 64) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "REFUSED: nothing consumed" in err
    assert "manifest sha256 does not match --expect-manifest-sha256" in err
    assert SENTINEL not in out + err


def test_missing_expected_sha256_prints_consistency_not_authenticity_warning(pair, capsys):
    """Semantic I: without --expect-manifest-sha256 a WARNING on stderr says the pair is checked for
    consistency only, not authenticity."""
    assert _main(*pair) == 0
    err = capsys.readouterr().err
    warning = [line for line in err.splitlines() if line.startswith("WARNING:")]
    assert len(warning) == 1
    assert "--expect-manifest-sha256" in warning[0]
    assert "consistency" in warning[0] and "authenticity" in warning[0]


def _forge_pair(tmp_path, mark_requested):
    """A pair written by someone who can write both files: their own run, re-bound by hand."""
    result = _run(["forged downstream instruction " + SENTINEL])
    manifest = result.manifest()
    assert manifest["run"]["export_requested"] is False
    if mark_requested:
        manifest["run"]["export_requested"] = True  # verify_export requires it
    mbytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    export = {"schema": EXPORT_SCHEMA, "manifest_schema": MANIFEST_SCHEMA,
              "manifest_sha256": hashlib.sha256(mbytes).hexdigest(), "policy_name": POLICY_NAME,
              "records": [a.to_export_dict() for a in result.admitted]}
    mpath, epath = tmp_path / "forged-manifest.json", tmp_path / "forged-export.json"
    mpath.write_bytes(mbytes)
    _dump(epath, export)
    return mpath, epath


def test_forged_consistent_pair_is_refused_only_by_expected_sha256(pair, tmp_path, capsys):
    """Semantic I: a self-consistent forged pair passes the consistency checks (with the WARNING), and
    is refused, nothing consumed, when --expect-manifest-sha256 names the trusted run."""
    trusted = _msha(pair[0])
    mpath, epath = _forge_pair(tmp_path, mark_requested=True)
    assert verify_export(_load(epath), _load(mpath), manifest_bytes=mpath.read_bytes()) == []
    assert _main(mpath, epath) == 0
    assert "WARNING" in capsys.readouterr().err
    assert _main(mpath, epath, "--expect-manifest-sha256", trusted) == 2
    out, err = capsys.readouterr()
    assert out == "" and "manifest sha256 does not match --expect-manifest-sha256" in err
    assert SENTINEL not in out + err


def test_forged_pair_without_export_request_is_refused(tmp_path):
    """Semantic I/E: a forged pair whose manifest does not record export_requested is refused."""
    mpath, epath = _forge_pair(tmp_path, mark_requested=False)
    assert "manifest does not record that an export was requested" in _refused(mpath, epath)


def test_manifest_written_before_export_is_refused(tmp_path, capsys):
    """Semantic I/D: the old write_manifest-then-write_export order yields a pair the consumer refuses."""
    result = _run()
    mpath, epath = tmp_path / "m.json", tmp_path / "e.json"
    write_manifest(result, mpath)
    write_export(result, epath)
    problems = _refused(mpath, epath)
    assert "manifest does not record that an export was requested" in problems
    assert _main(mpath, epath) == 2
    assert SENTINEL not in "".join(capsys.readouterr())


# (11) duplicate JSON keys --------------------------------------------------------

@pytest.mark.parametrize("which,old,new", [
    ("manifest", '"index":0,', '"index":0,"index":0,'),
    ("export", '"index":0,', '"index":0,"index":0,'),
    ("export", '"text":', '"text":"shadow ' + SENTINEL + '","text":'),
    ("export", '"schema":', '"schema":"x","schema":'),
], ids=["manifest-nested-same-value", "export-nested-same-value", "export-text-shadow", "export-top-level"])
def test_duplicate_json_keys_refused(pair, capsys, which, old, new):
    """Semantic I/F: a manifest or export with a duplicate JSON object key (any depth) is refused as
    'cannot read <file> (ValueError)', exit 2, nothing consumed, no value echoed."""
    mpath, epath = pair
    target = mpath if which == "manifest" else epath
    raw = target.read_text(encoding="utf-8")
    assert old in raw
    target.write_text(raw.replace(old, new, 1), encoding="utf-8")
    assert _refused(mpath, epath) == [f"cannot read {which} (ValueError)"]
    assert _main(mpath, epath) == 2
    out, err = capsys.readouterr()
    assert out == "" and f"cannot read {which} (ValueError)" in err
    assert SENTINEL not in out + err
