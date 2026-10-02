"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
check   Inspect stdin through the live pipeline and print a forwarding decision.
serve   Start the persistent HTTP detection server.
demo    Run the offline replay demo (default) or a loopback live contrast.
screen  Pre-screen a JSONL batch of documents/messages, one verdict per item.
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

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
