"""
ingest_consumer.py — minimal downstream consumer of a little-canary ingest export

Produce the pair first (the export is opt-in and holds admitted records only):

    little-canary ingest records.jsonl --manifest manifest.json --export admitted.json

Then consume it:

    python examples/ingest_consumer.py --manifest manifest.json --export admitted.json

All-or-nothing: the consumer verifies the whole pair before handing anything
downstream. On any problem it exits 2 having consumed nothing. It does not trust
the export alone: every exported record is re-checked against the manifest
(admitted, coverage complete, detection none) and its hashes are recomputed here.

"Admitted" means the record completed the configured checks and satisfied policy;
it is not a statement that the content is harmless. The consumer never prints
record text, ids, sources or metadata values — only indices, lengths and states.

No network, no Ollama: this file only reads two JSON documents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from typing import Any, Callable

from little_canary import verify_export
from little_canary.ingest import HOLD_REASONS, loads_strict


class Refused(Exception):
    """The pair failed verification; nothing was handed downstream."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__(f"{len(problems)} problem(s)")
        self.problems = list(problems)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _material_sha256(rec: dict[str, Any]) -> str:
    """SPEC §3 formula, recomputed independently of little_canary.ingest."""
    doc = {
        "id": rec.get("id"),
        "source": rec.get("source"),
        "metadata": dict(sorted(rec["metadata"].items())),
        "text": rec["text"],
    }
    blob = json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _load(path: str, label: str) -> Any:
    return _load_with_bytes(path, label)[0]


def _load_with_bytes(path: str, label: str) -> tuple[Any, bytes]:
    # Only the exception type is reported: decoder messages can quote file bytes.
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        return loads_strict(raw.decode("utf-8")), raw  # duplicate keys are refused, never resolved
    except (OSError, ValueError, RecursionError, TypeError, MemoryError) as exc:
        raise Refused([f"cannot read {label} ({type(exc).__name__})"]) from None


def verified_records(
    manifest: Any, export: Any, *, manifest_bytes: bytes | None = None
) -> list[dict[str, Any]]:
    """Return the export's records only if the whole pair verifies; else raise Refused.

    Pass ``manifest_bytes`` (the raw manifest file) so the export's hash is also
    checked against the exact bytes on disk, not only the parsed document.
    """
    # 1. The library check: schemas, manifest hash binding, admitted set, hashes.
    try:
        problems = verify_export(export, manifest, manifest_bytes=manifest_bytes)
    except (TypeError, ValueError, RecursionError, AttributeError, KeyError, OverflowError, MemoryError) as exc:
        raise Refused([f"verification failed ({type(exc).__name__})"]) from None
    if problems:
        raise Refused(problems)

    # 2. Belt and braces: re-check every record against the manifest ourselves,
    #    without assuming step 1 validated the document structure.
    try:
        by_index: dict[int, dict[str, Any]] = {}
        for mrec in manifest["records"]:
            idx: Any = mrec.get("index") if isinstance(mrec, dict) else None
            if not _is_int(idx):
                continue  # nothing exported can match it; never echo its value
            if idx in by_index:
                problems.append(f"record {idx}: duplicated in manifest")
            by_index[idx] = mrec
        seen: set[int] = set()
        for rec in export["records"]:
            if not _is_int(rec["index"]):
                raise TypeError("export index")  # never echo a non-integer index
            label = f"record {rec['index']}"
            if rec["index"] in seen:
                problems.append(f"{label}: duplicated in export")
            seen.add(rec["index"])
            mrec = by_index.get(rec["index"], {})
            if not (
                mrec.get("admission") == "admitted"
                and mrec.get("hold_reasons") == []
                and mrec.get("coverage") == "complete"
                and mrec.get("detection") == "none"
            ):
                problems.append(f"{label}: not admitted in manifest")
            sha = _sha256(rec["text"])
            if not (rec["sha256"] == sha == mrec.get("sha256")):
                problems.append(f"{label}: sha256 does not match the text")
            material = _material_sha256(rec)
            if not (rec["material_sha256"] == material == mrec.get("material_sha256")):
                problems.append(f"{label}: material_sha256 does not match")
    except (KeyError, TypeError, AttributeError, ValueError):
        problems.append("export or manifest structure invalid")
    if problems:
        raise Refused(problems)
    return list(export["records"])


def consume_documents(
    manifest: Any,
    export: Any,
    downstream: Callable[[dict[str, Any]], None],
    *,
    manifest_bytes: bytes | None = None,
) -> list[int]:
    """Verify already-loaded documents, then hand each admitted record downstream once."""
    records = verified_records(manifest, export, manifest_bytes=manifest_bytes)  # raises before anything is consumed
    consumed = []
    for rec in records:
        downstream(rec)
        consumed.append(rec["index"])
    return consumed


def consume(
    manifest_path: str, export_path: str, downstream: Callable[[dict[str, Any]], None]
) -> list[int]:
    """Load and verify the pair, then hand each admitted record to ``downstream`` exactly once.

    Raises ``Refused`` (before any downstream call) if anything fails to load or verify.
    Returns the consumed indices in export order.
    """
    manifest, manifest_bytes = _load_with_bytes(manifest_path, "manifest")
    export = _load(export_path, "export")
    return consume_documents(manifest, export, downstream, manifest_bytes=manifest_bytes)


def _stub_downstream(rec: dict[str, Any]) -> None:
    # Stand-in for your application. Prints index and length only, never text.
    print(f"  consumed record {rec['index']} ({len(rec['text'])} chars)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consume a verified little-canary ingest export.")
    parser.add_argument("--manifest", required=True, help="manifest JSON written by `little-canary ingest`")
    parser.add_argument("--export", required=True, help="export JSON written by `little-canary ingest --export`")
    parser.add_argument(
        "--expect-manifest-sha256",
        default=None,
        help=(
            "The manifest sha256 printed by the `little-canary ingest` run you trust. "
            "Verification without it proves only that the two files are consistent with "
            "each other, not that they came from a screening run."
        ),
    )
    args = parser.parse_args(argv)

    try:
        manifest, manifest_bytes = _load_with_bytes(args.manifest, "manifest")
        export = _load(args.export, "export")
        if args.expect_manifest_sha256 is not None:
            actual = hashlib.sha256(manifest_bytes).hexdigest()
            if actual != args.expect_manifest_sha256.strip().lower():
                raise Refused(["manifest sha256 does not match --expect-manifest-sha256"])
        else:
            print(
                "WARNING: no --expect-manifest-sha256 given; the pair is checked for consistency only, "
                "not for authenticity (anyone who can write both files can forge a matching pair)",
                file=sys.stderr,
            )
        consumed = consume_documents(manifest, export, _stub_downstream, manifest_bytes=manifest_bytes)
    except Refused as refusal:
        print("REFUSED: nothing consumed", file=sys.stderr)
        for problem in refusal.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    print(f"consumed indices (verified against the manifest): {consumed}")
    # Why the others were not exported: known hold-reason names only, never labels or text.
    for mrec in manifest["records"]:
        if isinstance(mrec, dict) and _is_int(mrec.get("index")) and mrec.get("admission") != "admitted":
            raw = mrec.get("hold_reasons")
            reasons = [r for r in raw if r in HOLD_REASONS] if isinstance(raw, list) else []
            print(f"  held record {mrec['index']}: {', '.join(reasons) or 'unspecified'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
