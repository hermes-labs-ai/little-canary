"""
langchain_example.py - Little Canary in front of a LangChain runnable

Screens the user's prompt before invoking the downstream model or chain.
Degraded Little Canary coverage is surfaced and held instead of treated as a
clean pass.

Little Canary is a sensing layer, not a guarantee.

Requirements:
  - pip install langchain-core
  - Ollama running with a small model: ollama pull qwen2.5:1.5b
"""

from __future__ import annotations

from typing import Any

from little_canary import SecurityPipeline

LANGCHAIN_UNAVAILABLE = (
    "LangChain is not installed. Install a LangChain runtime in your application "
    "environment, for example `pip install langchain-core`; little-canary does "
    "not install LangChain for you."
)

pipeline = SecurityPipeline(canary_model="qwen2.5:1.5b", mode="full")


def _advisory_to_dict(advisory: Any) -> dict[str, Any] | None:
    if advisory is None:
        return None
    return {
        "flagged": advisory.flagged,
        "severity": advisory.severity,
        "signals": list(advisory.signals),
        "message": advisory.message,
        "system_prefix": advisory.to_system_prefix(),
    }


def _verdict_to_response(verdict: Any) -> dict[str, Any]:
    return {
        "safe": verdict.safe,
        "degraded": verdict.degraded,
        "summary": verdict.summary,
        "blocked_by": verdict.blocked_by,
        "canary_status": verdict.canary_status,
        "analysis_status": verdict.analysis_status,
        "advisory": _advisory_to_dict(verdict.advisory),
    }


def _prompt_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("input", "question", "message", "prompt"):
            text = value.get(key)
            if isinstance(text, str):
                return text
    return ""


def screen_prompt(value: Any, *, checker: Any = pipeline) -> dict[str, Any]:
    """Extract and screen user input before the downstream runnable is invoked."""
    prompt = _prompt_text(value)
    if not prompt.strip():
        return {
            "status": "unscreened",
            "allowed": False,
            "message": "No user prompt text was available to screen.",
            "prompt": prompt,
            "verdict": None,
        }

    verdict = checker.check(prompt)
    verdict_payload = _verdict_to_response(verdict)

    if verdict.degraded:
        return {
            "status": "degraded",
            "allowed": False,
            "message": "Little Canary coverage degraded; treating this input as unscreened.",
            "prompt": prompt,
            "verdict": verdict_payload,
        }

    if not verdict.safe:
        return {
            "status": "blocked",
            "allowed": False,
            "message": "Little Canary reported unsafe input.",
            "prompt": prompt,
            "verdict": verdict_payload,
        }

    advisory_prefix = verdict.advisory.to_system_prefix() if verdict.advisory else ""
    return {
        "status": "screened",
        "allowed": True,
        "prompt": prompt,
        "advisory_prefix": advisory_prefix,
        "verdict": verdict_payload,
    }


def call_runnable(target: Any, prompt: str) -> Any:
    """Call a LangChain-style runnable or a plain function."""
    if hasattr(target, "invoke"):
        return target.invoke(prompt)
    return target(prompt)


def answer_after_screening(screened: dict[str, Any], *, target: Any) -> dict[str, Any]:
    """Invoke the downstream runnable only after exercised-safe screening."""
    if not screened["allowed"]:
        return screened

    prompt = screened["prompt"]
    advisory_prefix = screened.get("advisory_prefix") or ""
    model_input = f"{advisory_prefix}\n\n{prompt}" if advisory_prefix else prompt
    return {
        "status": "answered",
        "allowed": True,
        "output": call_runnable(target, model_input),
        "verdict": screened["verdict"],
    }


def build_chain(target: Any, *, checker: Any = pipeline) -> Any:
    """Build a LangChain runnable, importing LangChain only when requested."""
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:  # pragma: no cover - exercised with sys.modules stubs
        raise RuntimeError(LANGCHAIN_UNAVAILABLE) from exc

    return RunnableLambda(lambda value: screen_prompt(value, checker=checker)) | RunnableLambda(
        lambda screened: answer_after_screening(screened, target=target)
    )


def demo_model(prompt: str) -> str:
    """Replace with your chat model runnable."""
    return f"[Production model would respond to: {prompt[:80]}...]"


if __name__ == "__main__":
    try:
        chain = build_chain(demo_model)
    except RuntimeError as exc:
        print(exc)
    else:
        print(chain.invoke({"question": "What is the capital of France?"}))
