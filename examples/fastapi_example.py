"""
fastapi_example.py - Little Canary in front of a FastAPI chat endpoint

Screens a request body before the application calls its model. This example is
fail-closed for degraded Little Canary coverage: degraded means unscreened, not
clean.

Little Canary is a sensing layer, not a guarantee.

Requirements:
  - pip install fastapi uvicorn
  - Ollama running with a small model: ollama pull qwen2.5:1.5b

Run:
  uvicorn "examples.fastapi_example:create_app" --factory
"""

from __future__ import annotations

from typing import Any

from little_canary import SecurityPipeline

FASTAPI_UNAVAILABLE = (
    "FastAPI is not installed. Install it in your application environment with "
    "`pip install fastapi uvicorn`; little-canary does not install FastAPI for you."
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


def call_model(*, user_message: str, system_prompt: str = "") -> str:
    """Replace with your production model call."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})
    return f"[Production model would receive {len(messages)} message(s)]"


def screen_then_answer(
    message: str,
    *,
    checker: Any = pipeline,
    model: Any = call_model,
) -> dict[str, Any]:
    """Screen input before the model call and return an API-shaped payload."""
    verdict = checker.check(message)
    verdict_payload = _verdict_to_response(verdict)

    if verdict.degraded:
        return {
            "status": "degraded",
            "allowed": False,
            "message": "Little Canary coverage degraded; treating this input as unscreened.",
            "verdict": verdict_payload,
        }

    if not verdict.safe:
        return {
            "status": "blocked",
            "allowed": False,
            "message": "Little Canary reported unsafe input.",
            "verdict": verdict_payload,
        }

    advisory_system_prompt = verdict.advisory.to_system_prefix() if verdict.advisory else ""
    return {
        "status": "answered",
        "allowed": True,
        "response": model(user_message=message, system_prompt=advisory_system_prompt),
        "verdict": verdict_payload,
    }


def create_app(*, checker: Any = pipeline, model: Any = call_model) -> Any:
    """Create the FastAPI app, importing FastAPI only when the app is requested."""
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as exc:  # pragma: no cover - exercised with sys.modules stubs
        raise RuntimeError(FASTAPI_UNAVAILABLE) from exc

    app = FastAPI(title="Little Canary FastAPI example")

    @app.post("/chat")
    def chat(payload: dict[str, Any]) -> dict[str, Any]:
        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            raise HTTPException(status_code=400, detail="Request body must include a non-empty 'message' string.")

        result = screen_then_answer(message, checker=checker, model=model)
        if not result["allowed"]:
            status_code = 503 if result["status"] == "degraded" else 403
            raise HTTPException(status_code=status_code, detail=result)
        return result

    return app


if __name__ == "__main__":
    try:
        create_app()
    except RuntimeError as exc:
        print(exc)
