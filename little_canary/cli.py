"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
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
    screen_parser.add_argument("--canary-model", default="qwen2.5:1.5b")
    screen_parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    screen_parser.add_argument("--timeout", type=timeout_type, default=None)
    screen_parser.add_argument(
        "--max-items", type=int, default=1000,
        help="Refuse batches larger than this instead of truncating (default: 1000)",
    )
    return parser


def _run_screen(args) -> int:
    """Exit 0: at least one item and all pass; 1: any block/flag; 2: else (degraded/unexercised, empty, bad input)."""
    import json
    import sys

    from little_canary.batch import STATE_BLOCK, STATE_FLAG, STATE_PASS, read_jsonl, screen_batch
    from little_canary.pipeline import SecurityPipeline

    try:
        if args.input == "-":
            items = list(read_jsonl(sys.stdin))
        else:
            with open(args.input, encoding="utf-8") as handle:
                items = list(read_jsonl(handle))
        timeout = args.timeout if args.timeout is not None else _default_timeout()
        pipeline = SecurityPipeline(
            canary_model=args.canary_model,
            ollama_url=args.ollama_url,
            mode=args.mode,
            canary_timeout=timeout,
        )
        result = screen_batch(pipeline, items, max_items=args.max_items)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict()))
    counts = result.counts
    if counts[STATE_BLOCK] or counts[STATE_FLAG]:
        return 1
    if not result.items:
        return 2  # nothing was screened: not a clean result
    return 0 if counts[STATE_PASS] == len(result.items) else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()

    args = parser.parse_args(argv)

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
