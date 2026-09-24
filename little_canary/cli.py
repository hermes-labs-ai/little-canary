"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
check   Inspect stdin through the live pipeline and print a forwarding decision.
serve   Start the persistent HTTP detection server.
demo    Run an explicit replay-admission or loopback live contrast.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

MIN_PORT = 0
MAX_PORT = 65535


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

    if args.command == "check":
        from little_canary import SecurityPipeline
        from little_canary.demo import validate_loopback_endpoint

        if args.context_model and not args.document:
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

            result = inspect_document(pipeline, text, context_model=args.context_model)
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
