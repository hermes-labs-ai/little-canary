"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
serve   Start the persistent HTTP detection server.
demo    Run an explicit replay-admission or loopback live contrast.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


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
        type=int,
        default=18421,
        help="TCP port to bind on localhost (default: 18421)",
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

    # -- demo ---------------------------------------------------------------
    demo_parser = subparsers.add_parser(
        "demo",
        help="Run a replay-admission or loopback live behavioral contrast",
    )
    run_kind = demo_parser.add_mutually_exclusive_group()
    run_kind.add_argument(
        "--replay",
        action="store_true",
        help="Verify an admitted packaged capture without egress; fail unavailable if absent",
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
        "--json",
        action="store_true",
        help="Emit the stable little-canary-demo/v1 result as JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()

    args = parser.parse_args(argv)

    if args.command == "serve":
        from little_canary.server import run_server

        run_server(
            port=args.port,
            mode=args.mode,
            canary_model=args.canary_model,
            ollama_url=args.ollama_url,
        )
        return 0

    if args.command == "demo":
        from little_canary.demo import run_live, run_replay

        if args.replay:
            return run_replay(output_json=args.json)
        if args.live:
            return run_live(
                endpoint=args.endpoint,
                backend=args.backend,
                model=args.model,
                output_json=args.json,
            )
        print(
            "usage: little-canary demo (--replay | --live) [--json] [--model MODEL] [--endpoint LOOPBACK_ORIGIN]",
            file=sys.stderr,
        )
        print(
            "\nChoose exactly one run kind: --replay or --live. No mode is inferred.",
            file=sys.stderr,
        )
        return 2

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
