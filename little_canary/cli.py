"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
check   Inspect stdin through the live pipeline and print a forwarding decision.
serve   Start the persistent HTTP detection server.
demo    Run the offline replay demo (default) or a loopback live contrast.
screen  Pre-screen a JSONL batch of documents/messages, one verdict per item.
ingest  (Experimental) Admit or hold JSONL records; write a manifest and optional export.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

MIN_PORT = 0
MAX_PORT = 65535

#: Default per-call canary timeout (seconds) for the CLI demo and server.
#: Worst single call measured on CPU-only hardware was ~383 s for a full
#: 256-token canary response; 600 s leaves headroom while staying bounded.
#: Operators on faster hardware can lower it with --timeout / LITTLE_CANARY_TIMEOUT.
DEFAULT_CANARY_TIMEOUT = 600.0

#: Environment variable that overrides the default canary timeout when the
#: corresponding --timeout flag is not given.
TIMEOUT_ENV_VAR = "LITTLE_CANARY_TIMEOUT"


def _default_timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV_VAR)
    if raw is None or not raw.strip():
        return DEFAULT_CANARY_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(
            f"error: {TIMEOUT_ENV_VAR}={raw!r} is not a valid number of seconds"
        ) from None
    if value <= 0:
        raise SystemExit(
            f"error: {TIMEOUT_ENV_VAR} must be a positive number of seconds"
        )
    return value


def timeout_type(value: str) -> float:
    """argparse type: a positive number of seconds."""
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid timeout: {value!r} is not a number of seconds"
        ) from None
    if timeout <= 0:
        raise argparse.ArgumentTypeError(
            f"invalid timeout: {timeout} must be a positive number of seconds"
        )
    return timeout


def port_type(value: str) -> int:
    """argparse type: a bind port integer in the inclusive range 0..65535.

    Port 0 is retained so callers can request an OS-assigned ephemeral port.
    """
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r} is not an integer") from None
    if port < MIN_PORT or port > MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"invalid port: {port} is outside the valid range {MIN_PORT}..{MAX_PORT}"
        )
    return port


def build_parser() -> argparse.ArgumentParser:
    from little_canary import __version__

    parser = argparse.ArgumentParser(
        prog="little-canary",
        description="Prompt injection detection via sacrificial LLM probes",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"little-canary {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser(
        "check", help="Inspect stdin through the live local pipeline (0=forward, 1=block, 2=insufficient)",
    )
    check_parser.add_argument("--document", action="store_true", help="Inspect fetched text in overlapping chunks; hold incomplete coverage")
    check_parser.add_argument("--context-model", help="With --document, use this Ollama model for contextual document classification")
    check_parser.add_argument("--model", default="qwen2.5:1.5b", help="Installed Ollama model tag")
    check_parser.add_argument("--endpoint", default="http://127.0.0.1:11434", help="Loopback Ollama HTTP origin")
    check_parser.add_argument("--timeout", type=float, default=60.0, help="Model request timeout, 1..300 seconds")

    # -- serve --------------------------------------------------------------
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the persistent HTTP detection server",
    )
    serve_parser.add_argument(
        "--port",
        type=port_type,
        default=18421,
        help="TCP port to bind on localhost, 0..65535 (default: 18421)",
    )
    serve_parser.add_argument(
        "--mode",
        choices=["block", "advisory", "full"],
        default="advisory",
        help="Pipeline mode (default: advisory)",
    )
    serve_parser.add_argument(
        "--canary-model",
        default="qwen2.5:1.5b",
        help="Ollama model tag for the canary probe (default: qwen2.5:1.5b)",
    )
    serve_parser.add_argument(
        "--ollama-url",
        default="http://127.0.0.1:11434",
        help="Explicit Ollama origin (default: http://127.0.0.1:11434)",
    )
    serve_parser.add_argument(
        "--timeout",
        type=timeout_type,
        default=None,
        help=(
            "Seconds to wait for one canary model call "
            f"(default: {TIMEOUT_ENV_VAR} or {DEFAULT_CANARY_TIMEOUT:g})"
        ),
    )

    # -- demo ---------------------------------------------------------------
    demo_parser = subparsers.add_parser(
        "demo",
        help=(
            "Run the offline replay demo (default), "
            "or an explicit loopback live contrast"
        ),
    )
    run_kind = demo_parser.add_mutually_exclusive_group()
    run_kind.add_argument(
        "--replay",
        action="store_true",
        help=(
            "Verify an admitted packaged capture without egress "
            "(this is also the default when neither flag is given)"
        ),
    )
    run_kind.add_argument(
        "--live",
        action="store_true",
        help="Exercise the fixed synthetic contrast against loopback Ollama",
    )
    demo_parser.add_argument(
        "--backend",
        choices=["ollama"],
        default="ollama",
        help="Live backend (only loopback Ollama is supported)",
    )
    demo_parser.add_argument(
        "--model",
        default="qwen2.5:1.5b",
        help="Exact Ollama model tag (default: qwen2.5:1.5b)",
    )
    demo_parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:11434",
        help="Literal loopback Ollama origin (default: http://127.0.0.1:11434)",
    )
    demo_parser.add_argument(
        "--timeout",
        type=timeout_type,
        default=None,
        help=(
            "Seconds to wait for one live canary model call "
            f"(default: {TIMEOUT_ENV_VAR} or {DEFAULT_CANARY_TIMEOUT:g})"
        ),
    )
    demo_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the stable little-canary-demo/v1 result as JSON",
    )

    # -- screen -------------------------------------------------------------
    screen_parser = subparsers.add_parser(
        "screen",
        help="Pre-screen a JSONL batch (each line a JSON string or {id, source, text})",
    )
    screen_parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSONL file to read, or - for stdin (default: -)",
    )
    screen_parser.add_argument(
        "--mode", choices=["block", "advisory", "full"], default="full",
        help="Pipeline mode (default: full)",
    )
    screen_parser.add_argument(
        "--canary-model", default="qwen2.5:1.5b",
        help="Ollama model tag for the canary probe (default: qwen2.5:1.5b)",
    )
    screen_parser.add_argument(
        "--ollama-url", default="http://127.0.0.1:11434",
        help="Explicit Ollama origin (default: http://127.0.0.1:11434)",
    )
    screen_parser.add_argument(
        "--timeout", type=timeout_type, default=None,
        help=f"Seconds per canary call (default: {TIMEOUT_ENV_VAR} or {DEFAULT_CANARY_TIMEOUT:g})",
    )
    screen_parser.add_argument(
        "--max-item-bytes", type=int, default=64 * 1024,
        help="Refuse any item whose text exceeds this many UTF-8 bytes (default: 65536)",
    )
    screen_parser.add_argument(
        "--max-total-bytes", type=int, default=8 * 1024 * 1024,
        help="Refuse batches whose texts total more than this many bytes (default: 8388608)",
    )
    screen_parser.add_argument(
        "--max-items", type=int, default=1000,
        help="Refuse batches larger than this instead of truncating (default: 1000)",
    )

    # -- ingest -------------------------------------------------------------
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="(Experimental) Admit or hold JSONL records; write a manifest and optional export",
        description=(
            "Experimental. Check every JSONL record ({text, id?, source?, metadata?} or a "
            "JSON string) and admit or hold it under the strict/v1 policy. Writes a "
            "manifest that carries no record text or metadata values (labels and key "
            "names appear in plaintext only for admitted records; label digests and a "
            "key count otherwise); "
            "--export writes admitted records only. Admitted means the record completed "
            "the configured checks and satisfied policy. Exit 0: every record admitted; "
            "1: held for detection only (blocked/flagged); 2: run completed but some "
            "record was held for an operational/coverage reason; 3: nothing was written "
            "(invalid input/config, empty input, an unreachable backend or unverifiable "
            "canary context, or a write failure)."
        ),
    )
    ingest_parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSONL file to read, or - for stdin (default: -)",
    )
    ingest_parser.add_argument(
        "--manifest", required=True, metavar="PATH",
        help="Where to write the evidence manifest (required)",
    )
    ingest_parser.add_argument(
        "--export", default=None, metavar="PATH",
        help="Also write an export of admitted records only (opt-in)",
    )
    ingest_parser.add_argument(
        "--overwrite", action="store_true",
        help=(
            "Replace existing manifest/export files: once the limits are validated, "
            "the previous pair is removed before the run starts, so a failed run never "
            "leaves a stale pair (default: refuse)"
        ),
    )
    ingest_parser.add_argument(
        "--mode", choices=["block", "advisory", "full"], default="full",
        help="Pipeline mode (default: full)",
    )
    ingest_parser.add_argument(
        "--canary-model", default="qwen2.5:1.5b",
        help="Ollama model tag for the canary probe (default: qwen2.5:1.5b)",
    )
    ingest_parser.add_argument(
        "--ollama-url", default="http://127.0.0.1:11434",
        help="Explicit Ollama origin (default: http://127.0.0.1:11434)",
    )
    ingest_parser.add_argument(
        "--timeout", type=timeout_type, default=None,
        help=f"Seconds per canary call (default: {TIMEOUT_ENV_VAR} or {DEFAULT_CANARY_TIMEOUT:g})",
    )
    ingest_parser.add_argument(
        "--segment-chars", type=int, default=3500,
        help=(
            "Max characters per checked segment; must not exceed the pipeline's "
            "max_input_length, 4000 (default: 3500)"
        ),
    )
    ingest_parser.add_argument(
        "--segment-overlap", type=int, default=500,
        help="Characters shared by consecutive segments (default: 500)",
    )
    ingest_parser.add_argument(
        "--max-segments", type=int, default=8,
        help="Per-record segment budget, text plus metadata; more is held over_budget (default: 8)",
    )
    ingest_parser.add_argument(
        "--max-item-bytes", type=int, default=64 * 1024,
        help=(
            "Hold any record whose text exceeds this many UTF-8 bytes (default: 65536); "
            "a single JSONL line longer than the reader's cap (6x this value plus room for "
            "labels and metadata) refuses the whole run"
        ),
    )
    ingest_parser.add_argument(
        "--max-items", type=int, default=1000,
        help="Refuse runs with more records than this (default: 1000)",
    )
    ingest_parser.add_argument(
        "--max-total-bytes", type=int, default=8 * 1024 * 1024,
        help="Refuse runs whose texts total more than this many bytes (default: 8388608)",
    )
    ingest_parser.add_argument(
        "--max-metadata-keys", type=int, default=32,
        help="Max metadata keys per record; more is malformed (default: 32)",
    )
    ingest_parser.add_argument(
        "--max-metadata-value-chars", type=int, default=1024,
        help="Max characters per metadata value; more is malformed (default: 1024)",
    )
    ingest_parser.add_argument(
        "--json", action="store_true",
        help="Print the manifest JSON to stdout instead of the summary",
    )
    return parser


def _run_screen(args) -> int:
    """Exit 2: empty/invalid input or any degraded/unexercised item (coverage hold wins);
    1: else any block/flag; 0: non-empty and all pass."""
    import json
    import sys

    from little_canary.batch import (
        MAX_ITEM_BYTES_CEILING,
        STATE_BLOCK,
        STATE_DEGRADED,
        STATE_FLAG,
        STATE_UNEXERCISED,
        check_limit,
        max_line_chars,
        read_jsonl,
        screen_batch,
    )
    from little_canary.pipeline import SecurityPipeline

    try:
        timeout = args.timeout if args.timeout is not None else _default_timeout()
        pipeline = SecurityPipeline(
            canary_model=args.canary_model,
            ollama_url=args.ollama_url,
            mode=args.mode,
            canary_timeout=timeout,
        )
        limits = {
            "max_items": args.max_items,
            "max_item_bytes": args.max_item_bytes,
            "max_total_bytes": args.max_total_bytes,
        }
        for name, value in limits.items():
            check_limit(name, value, maximum=MAX_ITEM_BYTES_CEILING if name == "max_item_bytes" else None)
        # Items are consumed lazily and lines read in bounded chunks, so any limit
        # stops reading at the first violation without allocating the excess.
        line_cap = max_line_chars(args.max_item_bytes)
        if args.input == "-":
            result = screen_batch(pipeline, read_jsonl(sys.stdin, max_line=line_cap), **limits)
        else:
            with open(args.input, encoding="utf-8") as handle:
                result = screen_batch(pipeline, read_jsonl(handle, max_line=line_cap), **limits)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SystemExit as exc:  # invalid LITTLE_CANARY_TIMEOUT: report as invalid config
        if exc.code not in (None, 0):
            print(exc.code, file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict()))
    counts = result.counts
    if not result.items:
        return 2  # nothing was screened: not a clean result
    if counts[STATE_DEGRADED] or counts[STATE_UNEXERCISED]:
        return 2  # a coverage hold is never masked by a block/flag elsewhere in the batch
    if counts[STATE_BLOCK] or counts[STATE_FLAG]:
        return 1
    return 0


def _same_path(a: str, b: str) -> bool:
    if os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _check_ingest_targets(args) -> str | None:
    """Return an error message if the output paths are unusable; nothing is written."""
    targets = [("--manifest", args.manifest)]
    if args.export is not None:
        targets.append(("--export", args.export))
        if _same_path(args.manifest, args.export):
            return "--manifest and --export must be different paths"
    for flag, path in targets:
        if args.input != "-" and _same_path(path, args.input):
            return f"{flag} must not be the input file"
        if os.path.isdir(path):
            return f"{flag} {path} is a directory"
        if os.path.lexists(path) and not args.overwrite:
            return f"{flag} {path} already exists (use --overwrite to replace it)"
    return None


def _ingest_exit_code(records) -> int:
    """2 if any record is held for an operational/coverage reason, else 1 if any is
    held for detection, else 0.

    ``incomplete`` on a record that is also ``blocked``/``flagged`` is the recorded
    consequence of that detection (checking stopped, or a structural block skipped
    the canary), so it counts as a detection hold, like the same input under
    ``screen``. ``incomplete`` without a detection reason is a coverage hold.
    """
    from little_canary.ingest import (
        HOLD_BLOCKED,
        HOLD_DEGRADED,
        HOLD_ERROR,
        HOLD_FLAGGED,
        HOLD_MALFORMED,
        HOLD_OVER_BUDGET,
        HOLD_UNEXERCISED,
    )

    operational = {HOLD_MALFORMED, HOLD_OVER_BUDGET, HOLD_DEGRADED, HOLD_UNEXERCISED, HOLD_ERROR}
    detection = {HOLD_BLOCKED, HOLD_FLAGGED}
    code = 0
    for rec in records:
        reasons = set(rec.hold_reasons)
        if not reasons:
            continue
        if reasons & operational or not reasons & detection:
            return 2
        code = 1
    return code


class _HashingReader:
    """readline() passthrough that digests every byte handed to the JSONL reader."""

    def __init__(self, handle):
        import hashlib

        self._handle = handle
        self._hash = hashlib.sha256()
        self.complete = False

    def readline(self, size=-1):
        line = self._handle.readline(size)
        if line == "":
            self.complete = True  # EOF reached: the digest covers the whole input
        else:
            self._hash.update(line.encode("utf-8"))
        return line

    def hexdigest(self):
        return self._hash.hexdigest() if self.complete else None


def _run_ingest(args) -> int:
    """Exit 3: nothing written (invalid input/config, empty input, write failure);
    2: run completed and written, but some record was held for an operational/coverage
    reason; 1: else some record held for detection; 0: non-empty and every record
    admitted. Record text is never printed."""
    import io
    import sys

    from little_canary.batch import MAX_ITEM_BYTES_CEILING, check_limit
    from little_canary.ingest import (
        POLICY_NAME,
        IngestPolicy,
        ingest_records,
        publish,
        read_records,
        required_canary_context,
    )
    from little_canary.pipeline import SecurityPipeline

    problem = _check_ingest_targets(args)
    if problem is not None:
        print(f"error: {problem}", file=sys.stderr)
        return 3

    try:
        limits = {
            "segment_chars": args.segment_chars,
            "segment_overlap": args.segment_overlap,
            "max_segments": args.max_segments,
            "max_item_bytes": args.max_item_bytes,
            "max_items": args.max_items,
            "max_total_bytes": args.max_total_bytes,
            "max_metadata_keys": args.max_metadata_keys,
            "max_metadata_value_chars": args.max_metadata_value_chars,
        }
        for name, value in limits.items():
            check_limit(name, value, maximum=MAX_ITEM_BYTES_CEILING if name == "max_item_bytes" else None)
        policy = IngestPolicy(**limits)
        policy.validate()
        timeout = args.timeout if args.timeout is not None else _default_timeout()
        if args.overwrite:
            # Local configuration is valid; consent to replace means the previous pair
            # is removed before the run starts, so a failed run never leaves a stale pair.
            for path in (args.manifest, args.export):
                if path is not None and os.path.lexists(path):
                    os.unlink(path)
        pipeline = SecurityPipeline(
            canary_model=args.canary_model,
            ollama_url=args.ollama_url,
            mode=args.mode,
            canary_timeout=timeout,
        )
        # Size the canary's context window to the segment budget so a long segment is
        # never silently truncated by the backend while the manifest calls it exercised.
        needed = required_canary_context(policy, pipeline)
        if needed is not None:
            pipeline = SecurityPipeline(
                canary_model=args.canary_model,
                ollama_url=args.ollama_url,
                mode=args.mode,
                canary_timeout=timeout,
                canary_num_ctx=needed,
            )
        for flag, path in (("--manifest", args.manifest), ("--export", args.export)):
            if path is not None and not os.access(os.path.dirname(os.path.abspath(path)) or ".", os.W_OK):
                raise OSError(f"{flag} directory is not writable: {os.path.dirname(os.path.abspath(path))}")
        reader_limits = {
            "max_item_bytes": args.max_item_bytes,
            "max_metadata_keys": args.max_metadata_keys,
            "max_metadata_value_chars": args.max_metadata_value_chars,
        }
        # All records are read and budgeted before the first check, so malformed
        # JSON or a run-level limit fails here with zero checks and nothing written.
        # The input is always decoded as strict UTF-8 (never the locale), and digested.
        if args.input == "-":
            raw = getattr(sys.stdin, "buffer", None)
            # Decode stdin as strict UTF-8 regardless of locale; a text-only stand-in
            # (tests) has no buffer and is used as-is.
            stream = (
                io.TextIOWrapper(raw, encoding="utf-8", errors="strict", newline="")
                if raw is not None
                else sys.stdin
            )
            reader = _HashingReader(stream)
            result = ingest_records(pipeline, read_records(reader, **reader_limits), policy=policy)
        else:
            with open(args.input, encoding="utf-8", errors="strict", newline="") as handle:
                reader = _HashingReader(handle)
                result = ingest_records(pipeline, read_records(reader, **reader_limits), policy=policy)
        result.input_sha256 = reader.hexdigest()
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except SystemExit as exc:  # invalid LITTLE_CANARY_TIMEOUT: report as invalid config
        if exc.code not in (None, 0):
            print(exc.code, file=sys.stderr)
        return 3

    if not result.records:
        print("error: no records in input; nothing written", file=sys.stderr)
        return 3

    try:
        digests = publish(result, args.manifest, args.export, overwrite=args.overwrite)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}; nothing written", file=sys.stderr)
        return 3
    manifest_sha = digests["manifest"]
    export_sha = digests.get("export")

    code = _ingest_exit_code(result.records)
    if args.json:
        print(result.manifest_json())
        return code

    counts = result.counts
    reasons = " ".join(f"{k}={v}" for k, v in counts["by_reason"].items() if v) or "none"
    outcome = {
        0: "every record admitted",
        1: "held for detection only (blocked/flagged)",
        2: "held for an operational/coverage reason",
    }[code]
    lines = [
        f"ingest ({POLICY_NAME}): {len(result.records)} records, "
        f"{counts['admitted']} admitted, {counts['held']} held",
        f"hold reasons: {reasons}",
        "detection: " + " ".join(f"{k}={v}" for k, v in counts["detection"].items()),
        "coverage: " + " ".join(f"{k}={v}" for k, v in counts["coverage"].items()),
        f"checks performed: {result.checks_performed}",
        f"input sha256={result.input_sha256}",
        f"manifest: {args.manifest} sha256={manifest_sha}",
        (
            f"export: {args.export} sha256={export_sha} ({len(result.admitted)} admitted records)"
            if export_sha is not None
            else "export: not requested"
        ),
        f"exit {code}: {outcome}",
    ]
    print("\n".join(lines))
    return code


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()

    args = parser.parse_args(argv)

    if args.command == "check":
        from little_canary import SecurityPipeline
        from little_canary.demo import validate_loopback_endpoint

        if args.context_model is not None:
            if not args.context_model.strip():
                parser.error("--context-model requires a nonempty model name")
            if not args.document:
                parser.error("--context-model requires --document")
        try:
            endpoint = validate_loopback_endpoint(args.endpoint)
            if not 1 <= args.timeout <= 300:
                raise ValueError("timeout must be from 1 to 300 seconds")
        except ValueError as exc:
            parser.error(str(exc))
        text = sys.stdin.read(24001 if args.document else 4001)
        if not args.document and (not text.strip() or len(text) > 4000):
            print("DECISION   BLOCK")
            print("INSPECTION NOT RUN — input must contain 1..4000 characters, including newlines")
            print("REASON     Invalid input; no injection finding and no model call")
            return 1
        pipeline = SecurityPipeline(
            canary_model=args.model, ollama_url=endpoint,
            canary_timeout=args.timeout, mode="block",
        )
        if args.document:
            from little_canary.documents import inspect_document

            try:
                result = inspect_document(pipeline, text, context_model=args.context_model)
            except Exception:
                print("DECISION   INSUFFICIENTLY INSPECTED")
                print("INSPECTION FAILED — document inspection did not return a result; do not forward")
                return 2
            print(f"DECISION   {result.decision}")
            print(f"INSPECTION {result.inspection}")
            print(f"COVERAGE   chunks={result.chunks_checked}/{result.chunks_total}; inspected_chars={result.chars_inspected}/{len(text)}")
            print(f"METHOD     {result.analysis_method}; model={args.context_model or args.model}")
            print(f"SUMMARY    {result.summary}")
            return {"FORWARD": 0, "BLOCK": 1, "INSUFFICIENTLY INSPECTED": 2}[result.decision]
        print(f"BACKEND    ollama; model={args.model}; endpoint={endpoint}")
        print("POLICY     block; structural + behavioral inspection; no automatic forwarding")
        try:
            verdict = pipeline.check(text)
        except Exception:
            print("DECISION   INSUFFICIENTLY INSPECTED")
            print("INSPECTION FAILED — check did not return a verdict; do not forward")
            return 2
        complete = verdict.canary_status == "exercised" and verdict.analysis_status == "exercised"
        flagged = verdict.advisory is not None and verdict.advisory.flagged
        if verdict.degraded:
            inspection = "DEGRADED — required inspection failed or was unavailable"
        elif not complete:
            inspection = "INCOMPLETE — behavioral inspection did not run"
        elif not verdict.safe or flagged:
            inspection = "SUCCESSFUL — signals detected; not clean"
        else:
            inspection = "CLEAN — enabled inspection completed without detected signals"
        if not verdict.safe:
            decision, exit_code = "BLOCK", 1
        elif verdict.degraded or not complete:
            decision, exit_code = "INSUFFICIENTLY INSPECTED", 2
        else:
            decision, exit_code = "FORWARD", 0
        print(f"DECISION   {decision}")
        print(f"INSPECTION {inspection}")
        print(f"COVERAGE   canary={verdict.canary_status}; analysis={verdict.analysis_method}/{verdict.analysis_status}")
        print(f"ROUTING    safe={verdict.safe}; degraded={verdict.degraded}; blocked_by={verdict.blocked_by}")
        print(f"RISK       {verdict.canary_risk_score if verdict.canary_risk_score is not None else 'unmeasured'}")
        for layer in verdict.layers:
            print(f"LAYER      {layer.layer_name}: {layer.status} — {layer.details}")
        if flagged and exit_code == 0:
            print(f"ADVISORY   {verdict.advisory.message}")
            print("NEXT       If forwarding, apply verdict.advisory.to_system_prefix() in your application")
        if exit_code == 2:
            print("NEXT       Hold input; check Ollama is running, the model is installed, and retry a fresh check")
        print(f"SUMMARY    {verdict.summary}")
        return exit_code

    if args.command == "serve":
        from little_canary.server import run_server

        timeout = args.timeout if args.timeout is not None else _default_timeout()
        run_server(
            port=args.port,
            mode=args.mode,
            canary_model=args.canary_model,
            ollama_url=args.ollama_url,
            canary_timeout=timeout,
        )
        return 0

    if args.command == "demo":
        from little_canary.demo import run_live, run_replay

        if args.live:
            timeout = args.timeout if args.timeout is not None else _default_timeout()
            return run_live(
                endpoint=args.endpoint,
                backend=args.backend,
                model=args.model,
                output_json=args.json,
                timeout=timeout,
            )
        # Bare `little-canary demo` and `demo --replay` both run the offline
        # replay: no model, no network, no extra dependencies.
        return run_replay(output_json=args.json)

    if args.command == "screen":
        return _run_screen(args)

    if args.command == "ingest":
        return _run_ingest(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
