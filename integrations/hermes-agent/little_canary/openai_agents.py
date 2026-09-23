"""
openai_agents.py - Optional OpenAI Agents SDK input-guardrail adapter

Screens the text an Agents SDK run receives through an injected Little Canary
checker before (or alongside) agent execution and reports the result as an SDK
``GuardrailFunctionOutput``.

Semantics are mapped truthfully rather than collapsed to a boolean:

  - ``unsafe``      the checker refused the input (``safe=False``); the SDK
                    tripwire fires.
  - ``safe``        behavioral coverage was exercised and found nothing.
  - ``flagged``     coverage was exercised and raised an advisory without
                    refusing routing (advisory/full mode).
  - ``degraded``    an enabled inspection dependency failed, or the checker
                    itself raised. This is never reported as a PASS.
  - ``unexercised`` no behavioral coverage ran (canary disabled, structural
                    only, or no screenable text in the input).

By default the adapter keeps Little Canary's fail-open routing: only ``unsafe``
trips the wire, and degraded or unexercised coverage stays visible in
``output_info``. ``on_degraded="fail_closed"`` trips the wire unless coverage is
exercised ``safe``.

The ``openai-agents`` package is optional. Importing this module never imports
it; only :func:`little_canary_input_guardrail` and
:meth:`ScreeningOutcome.to_guardrail_output` require it.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Union, cast

from .pipeline import PipelineVerdict

logger = logging.getLogger(__name__)

COVERAGE_SAFE = "safe"
COVERAGE_UNSAFE = "unsafe"
COVERAGE_FLAGGED = "flagged"
COVERAGE_DEGRADED = "degraded"
COVERAGE_UNEXERCISED = "unexercised"

POLICY_FAIL_OPEN = "fail_open"
POLICY_FAIL_CLOSED = "fail_closed"
VALID_POLICIES = (POLICY_FAIL_OPEN, POLICY_FAIL_CLOSED)

DEFAULT_GUARDRAIL_NAME = "little_canary"

_OPTIONAL_DEPENDENCY_HINT = (
    "The OpenAI Agents SDK is not installed. Install the optional extra with "
    "'pip install \"little-canary[openai-agents]\"' to use "
    "little_canary.openai_agents with the Agents SDK."
)

Checker = Union[Callable[[str], PipelineVerdict], Any]


@dataclass
class ScreeningOutcome:
    """Structured result of screening Agents SDK input through Little Canary.

    ``tripwire_triggered`` is the routing decision handed to the SDK.
    ``coverage`` states what was actually measured. A ``degraded`` or
    ``unexercised`` outcome with ``tripwire_triggered=False`` is a fail-open
    pass-through, not an inspected-safe result.
    """

    coverage: str
    tripwire_triggered: bool
    policy: str
    safe: bool | None = None
    degraded: bool = False
    canary_status: str = "disabled"
    analysis_method: str = "none"
    analysis_status: str = "not_applicable"
    risk_score: float | None = None
    signals: list[str] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    screened_chars: int = 0

    @property
    def exercised_safe(self) -> bool:
        """True only when behavioral coverage ran and found nothing."""
        return self.coverage == COVERAGE_SAFE

    def to_dict(self) -> dict[str, Any]:
        """Response-free dictionary suitable for logs or ``output_info``."""
        return {
            "coverage": self.coverage,
            "tripwire_triggered": self.tripwire_triggered,
            "policy": self.policy,
            "safe": self.safe,
            "degraded": self.degraded,
            "canary_status": self.canary_status,
            "analysis_method": self.analysis_method,
            "analysis_status": self.analysis_status,
            "risk_score": self.risk_score,
            "signals": list(self.signals),
            "summary": self.summary,
            "error": self.error,
            "screened_chars": self.screened_chars,
        }

    def to_guardrail_output(self) -> Any:
        """Convert to an SDK ``GuardrailFunctionOutput``. Requires ``openai-agents``."""
        sdk = _require_sdk()
        return sdk.GuardrailFunctionOutput(
            output_info=self.to_dict(),
            tripwire_triggered=self.tripwire_triggered,
        )


def _require_sdk() -> Any:
    # importlib keeps the optional SDK out of static import analysis so
    # ``mypy little_canary`` does not follow into the installed package.
    try:
        return importlib.import_module("agents")
    except ImportError as exc:
        raise ImportError(_OPTIONAL_DEPENDENCY_HINT) from exc


def _validate_policy(policy: str) -> str:
    if policy not in VALID_POLICIES:
        raise ValueError(f"on_degraded must be one of {VALID_POLICIES}, got {policy!r}")
    return policy


def extract_user_text(run_input: Any) -> str:
    """Return the user-authored text from an Agents SDK run input.

    Accepts the SDK's ``str | list[TResponseInputItem]`` shape. For a list,
    only message items with ``role == "user"`` are collected; string content
    and ``input_text`` parts are joined with newlines. Non-user items,
    tool outputs, images, and unknown shapes contribute nothing.
    """
    if isinstance(run_input, str):
        return run_input
    if not isinstance(run_input, (list, tuple)):
        return ""
    chunks: list[str] = []
    for item in run_input:
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, (list, tuple)):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "input_text" and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
    return "\n".join(chunk for chunk in chunks if chunk)


def _resolve_check(checker: Checker) -> Callable[[str], Any]:
    """Return the callable that screens text, or raise TypeError for an unusable checker."""
    check = getattr(checker, "check", None)
    if callable(check):
        return cast(Callable[[str], Any], check)
    if callable(checker):
        return cast(Callable[[str], Any], checker)
    raise TypeError("checker must expose .check(text) or be callable with text")


def _invoke_checker(check: Callable[[str], Any], text: str) -> PipelineVerdict:
    verdict = check(text)
    if not isinstance(verdict, PipelineVerdict):
        raise TypeError(f"checker returned {type(verdict).__name__}, expected PipelineVerdict")
    return verdict


def _classify(verdict: PipelineVerdict) -> str:
    advisory = verdict.advisory
    flagged = advisory is not None and advisory.flagged
    if not verdict.safe:
        return COVERAGE_UNSAFE
    if verdict.degraded:
        return COVERAGE_DEGRADED
    if flagged:
        return COVERAGE_FLAGGED
    if verdict.canary_status != "exercised" or verdict.analysis_status != "exercised":
        return COVERAGE_UNEXERCISED
    return COVERAGE_SAFE


def _tripwire_for(coverage: str, policy: str) -> bool:
    """Apply the caller's adapter policy without changing pipeline routing.

    Fail-open remains the default. The explicit fail-closed option is an
    application boundary, like the CLI integrations' failure-mode setting;
    it must still stop degraded checks when the caller selects that policy.
    """
    if coverage == COVERAGE_UNSAFE:
        return True
    if policy == POLICY_FAIL_CLOSED:
        return coverage != COVERAGE_SAFE
    return False


def screen_text(
    checker: Checker,
    text: str,
    *,
    on_degraded: str = POLICY_FAIL_OPEN,
) -> ScreeningOutcome:
    """Screen ``text`` with ``checker`` and map the verdict to a :class:`ScreeningOutcome`.

    ``checker`` is any object with ``check(text) -> PipelineVerdict`` (such as
    ``SecurityPipeline``) or a callable with the same contract. Exceptions from
    the checker, including a non-``PipelineVerdict`` return value, are contained
    and reported as ``degraded`` coverage; they are never re-raised and never
    reported as safe. A checker with neither shape raises ``TypeError`` before
    any screening happens.
    """
    policy = _validate_policy(on_degraded)
    check = _resolve_check(checker)
    screened_chars = len(text)

    if not text:
        coverage = COVERAGE_UNEXERCISED
        return ScreeningOutcome(
            coverage=coverage,
            tripwire_triggered=_tripwire_for(coverage, policy),
            policy=policy,
            summary="No screenable user text in run input.",
            screened_chars=0,
        )

    try:
        verdict = _invoke_checker(check, text)
    except Exception as exc:
        logger.error("Little Canary checker failed (%s)", type(exc).__name__)
        coverage = COVERAGE_DEGRADED
        return ScreeningOutcome(
            coverage=coverage,
            tripwire_triggered=_tripwire_for(coverage, policy),
            policy=policy,
            safe=None,
            degraded=True,
            canary_status="failed",
            analysis_method="none",
            analysis_status="failed",
            summary="Checker raised; behavioral coverage unavailable.",
            error=type(exc).__name__,
            screened_chars=screened_chars,
        )

    coverage = _classify(verdict)
    advisory = verdict.advisory
    signals = list(advisory.signals) if advisory is not None and advisory.signals else []
    return ScreeningOutcome(
        coverage=coverage,
        tripwire_triggered=_tripwire_for(coverage, policy),
        policy=policy,
        safe=verdict.safe,
        degraded=verdict.degraded,
        canary_status=verdict.canary_status,
        analysis_method=verdict.analysis_method,
        analysis_status=verdict.analysis_status,
        risk_score=verdict.canary_risk_score,
        signals=signals,
        summary=verdict.summary,
        screened_chars=screened_chars,
    )


async def screen_run_input(
    checker: Checker,
    run_input: Any,
    *,
    on_degraded: str = POLICY_FAIL_OPEN,
) -> ScreeningOutcome:
    """Async wrapper: extract user text, then run the blocking checker in a worker thread."""
    text = extract_user_text(run_input)
    return await asyncio.to_thread(screen_text, checker, text, on_degraded=on_degraded)


def little_canary_input_guardrail(
    checker: Checker,
    *,
    on_degraded: str = POLICY_FAIL_OPEN,
    name: str = DEFAULT_GUARDRAIL_NAME,
    run_in_parallel: bool = False,
) -> Any:
    """Build an Agents SDK ``InputGuardrail`` backed by a Little Canary checker.

    Requires the optional ``openai-agents`` package. ``run_in_parallel``
    defaults to ``False`` so the check completes before the agent starts; the
    SDK default would run it concurrently with the first model call.

    Usage::

        from agents import Agent
        from little_canary import SecurityPipeline
        from little_canary.openai_agents import little_canary_input_guardrail

        pipeline = SecurityPipeline(canary_model="qwen2.5:1.5b", mode="block")
        agent = Agent(
            name="assistant",
            input_guardrails=[little_canary_input_guardrail(pipeline)],
        )
    """
    sdk = _require_sdk()
    policy = _validate_policy(on_degraded)
    _resolve_check(checker)

    async def guardrail_function(ctx: Any, agent: Any, run_input: Any) -> Any:
        outcome = await screen_run_input(checker, run_input, on_degraded=policy)
        if outcome.coverage != COVERAGE_SAFE:
            logger.info(
                "Little Canary guardrail coverage=%s tripwire=%s policy=%s",
                outcome.coverage,
                outcome.tripwire_triggered,
                outcome.policy,
            )
        return outcome.to_guardrail_output()

    guardrail_function.__name__ = name
    return sdk.InputGuardrail(
        guardrail_function=guardrail_function,
        name=name,
        run_in_parallel=run_in_parallel,
    )


__all__ = [
    "COVERAGE_DEGRADED",
    "COVERAGE_FLAGGED",
    "COVERAGE_SAFE",
    "COVERAGE_UNEXERCISED",
    "COVERAGE_UNSAFE",
    "DEFAULT_GUARDRAIL_NAME",
    "POLICY_FAIL_CLOSED",
    "POLICY_FAIL_OPEN",
    "VALID_POLICIES",
    "ScreeningOutcome",
    "extract_user_text",
    "little_canary_input_guardrail",
    "screen_run_input",
    "screen_text",
]
