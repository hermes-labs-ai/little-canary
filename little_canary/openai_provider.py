"""
openai_provider.py - OpenAI-Compatible API Providers for Canary and Judge

Adds an adapter for endpoints that implement the OpenAI chat-completions
request and response subset used here. Provider compatibility must be tested
for the selected endpoint; the adapter is an alternative to Ollama.

Transport and protocol failures preserve fail-open routing, but are returned as
degraded/unexercised results rather than evidence of safety.

Usage:
    from little_canary.openai_provider import OpenAICanaryProbe, OpenAILLMJudge

    # MiniMax example
    probe = OpenAICanaryProbe(
        model="MiniMax-M2.5",
        api_key="your-minimax-key",
        base_url="https://api.minimax.io/v1",
    )
    result = probe.test("What is the capital of France?")

    # Example endpoint implementing the expected chat-completions subset
    probe = OpenAICanaryProbe(
        model="gpt-4o-mini",
        api_key="your-openai-key",
        base_url="https://api.openai.com/v1",
    )
"""

from __future__ import annotations

import logging
import re
import time

import requests  # type: ignore[import-untyped]

from .canary import DEFAULT_CANARY_SYSTEM_PROMPT, CanaryResult, _redacted_origin
from .judge import JUDGE_SYSTEM_PROMPT, AnalysisResult, Signal

logger = logging.getLogger(__name__)


class OpenAICanaryProbe:
    """
    Sends user input to a sacrificial LLM via an OpenAI-compatible API.

    Drop-in alternative to CanaryProbe for cloud or self-hosted endpoints
    that expose the ``/chat/completions`` API (OpenAI, MiniMax, Together,
    Groq, vLLM, etc.).

    Usage:
        probe = OpenAICanaryProbe(
            model="MiniMax-M2.5",
            api_key="your-key",
            base_url="https://api.minimax.io/v1",
        )
        result = probe.test("What is the capital of France?")
    """

    def __init__(
        self,
        model="gpt-4o-mini",
        api_key="",
        base_url="https://api.openai.com/v1",
        system_prompt=DEFAULT_CANARY_SYSTEM_PROMPT,
        timeout=10.0,
        max_tokens=256,
        temperature=0.0,
        seed=42,
    ):
        # type: (str, str, str, str, float, int, float, int) -> None
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.seed = seed

    def test(self, user_input):
        # type: (str) -> CanaryResult
        """
        Feed user input to the canary and capture its behavioral response.

        Uses the OpenAI ``/chat/completions`` endpoint format.
        """
        start_time = time.monotonic()

        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_input},
                ],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "stream": False,
            }
            # seed is not universally supported; include it for providers
            # that honour it (OpenAI, vLLM) and ignore it elsewhere.
            if self.seed is not None:
                payload["seed"] = self.seed

            url = f"{self.base_url}/chat/completions"
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )

            elapsed = time.monotonic() - start_time

            if response.status_code != 200:
                return CanaryResult(
                    response="",
                    latency=elapsed,
                    model=self.model,
                    system_prompt=self.system_prompt,
                    user_input=user_input,
                    success=False,
                    error=f"API returned HTTP status {response.status_code}",
                )

            try:
                data = response.json()
            except ValueError:
                return CanaryResult(
                    response="",
                    latency=elapsed,
                    model=self.model,
                    system_prompt=self.system_prompt,
                    user_input=user_input,
                    success=False,
                    error="API protocol error: invalid JSON response",
                )

            choices = data.get("choices") if isinstance(data, dict) else None
            first_choice = choices[0] if isinstance(choices, list) and choices else None
            message = first_choice.get("message") if isinstance(first_choice, dict) else None
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, str) or not content.strip():
                return CanaryResult(
                    response="",
                    latency=elapsed,
                    model=self.model,
                    system_prompt=self.system_prompt,
                    user_input=user_input,
                    success=False,
                    error=("API protocol error: response content must be a non-empty string"),
                )

            usage = data.get("usage", {})
            if not isinstance(usage, dict):
                usage = {}

            return CanaryResult(
                response=content,
                latency=elapsed,
                model=self.model,
                system_prompt=self.system_prompt,
                user_input=user_input,
                success=True,
                metadata={
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                },
            )

        except requests.Timeout:
            elapsed = time.monotonic() - start_time
            return CanaryResult(
                response="",
                latency=elapsed,
                model=self.model,
                system_prompt=self.system_prompt,
                user_input=user_input,
                success=False,
                error=f"Canary timed out after {self.timeout}s",
            )

        except requests.ConnectionError:
            elapsed = time.monotonic() - start_time
            return CanaryResult(
                response="",
                latency=elapsed,
                model=self.model,
                system_prompt=self.system_prompt,
                user_input=user_input,
                success=False,
                error=(f"Cannot connect to API at {_redacted_origin(self.base_url)}"),
            )

        except Exception as exc:
            elapsed = time.monotonic() - start_time
            error_class = type(exc).__name__
            logger.warning("OpenAI-compatible canary probe failed with %s", error_class)
            return CanaryResult(
                response="",
                latency=elapsed,
                model=self.model,
                system_prompt=self.system_prompt,
                user_input=user_input,
                success=False,
                error=f"Canary probe failed ({error_class})",
            )

    def is_available(self):
        # type: () -> bool
        """Check if the API endpoint is reachable with valid credentials."""
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            resp = requests.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=5,
            )
            return bool(resp.status_code == 200)
        except Exception:
            return False


class OpenAILLMJudge:
    """
    Uses a second LLM via an OpenAI-compatible API to classify whether
    the canary was compromised.

    Drop-in alternative to LLMJudge for cloud or self-hosted endpoints.

    Usage:
        judge = OpenAILLMJudge(
            model="MiniMax-M2.5",
            api_key="your-key",
            base_url="https://api.minimax.io/v1",
        )
        result = judge.analyze(canary_result)
    """

    def __init__(
        self,
        model="gpt-4o-mini",
        api_key="",
        base_url="https://api.openai.com/v1",
        timeout=15.0,
        temperature=0.0,
        seed=42,
        max_tokens=512,
    ):
        # type: (str, str, str, float, float, int, int) -> None
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.seed = seed
        self.max_tokens = max_tokens
        # Kept for interface compatibility with BehavioralAnalyzer
        self.block_threshold = 0.5

    @staticmethod
    def _failure(
        canary_result,
        summary,
        *,
        canary_status="exercised",
        analysis_status="failed",
    ):
        # type: (CanaryResult, str, str, str) -> AnalysisResult
        """Return fail-open routing without inventing a safety measurement."""
        return AnalysisResult(
            risk_score=None,
            should_block=False,
            canary_result=canary_result,
            summary=summary,
            degraded=True,
            canary_status=canary_status,
            analysis_method="llm_judge",
            analysis_status=analysis_status,
        )

    def analyze(self, canary_result):
        # type: (CanaryResult) -> AnalysisResult
        """
        Ask the judge LLM whether the canary's response shows compromise.

        Returns AnalysisResult with the same interface as BehavioralAnalyzer.
        """
        if not canary_result.success:
            return self._failure(
                canary_result,
                (
                    "Canary probe failed. Judge analysis was not run; "
                    "fail-open routing applies."
                ),
                canary_status="failed",
                analysis_status="not_applicable",
            )

        judge_input = f"User message:\n{canary_result.user_input}\n\nAssistant response:\n{canary_result.response}"

        try:
            start = time.monotonic()

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": judge_input},
                ],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "stream": False,
            }
            if self.seed is not None:
                payload["seed"] = self.seed

            url = f"{self.base_url}/chat/completions"
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            elapsed = time.monotonic() - start

            if response.status_code != 200:
                logger.warning("Judge returned HTTP status %d", response.status_code)
                return self._failure(
                    canary_result,
                    (f"Judge error (status {response.status_code}). Analysis incomplete; fail-open routing applies."),
                )

            try:
                data = response.json()
            except ValueError:
                return self._failure(
                    canary_result,
                    "Judge returned invalid JSON. Analysis incomplete; fail-open routing applies.",
                )

            choices = data.get("choices") if isinstance(data, dict) else None
            first_choice = choices[0] if isinstance(choices, list) and choices else None
            message = first_choice.get("message") if isinstance(first_choice, dict) else None
            raw_output = message.get("content") if isinstance(message, dict) else None
            if not isinstance(raw_output, str) or not raw_output.strip():
                return self._failure(
                    canary_result,
                    ("Judge response content was missing or invalid. Analysis incomplete; fail-open routing applies."),
                )

            verdict = self._parse_verdict(raw_output)

            if verdict == "UNSAFE":
                return AnalysisResult(
                    risk_score=1.0,
                    should_block=True,
                    signals=[
                        Signal(
                            category="llm_judge",
                            description="LLM judge classified canary response as compromised",
                            severity=1.0,
                            evidence=canary_result.response[:150],
                        )
                    ],
                    canary_result=canary_result,
                    summary=f"BLOCKED by LLM judge ({elapsed:0.2f}s). Canary response classified as compromised.",
                    hard_blocked=True,
                )
            if verdict == "SAFE":
                return AnalysisResult(
                    risk_score=0.0,
                    should_block=False,
                    canary_result=canary_result,
                    summary=f"LLM judge: SAFE ({elapsed:0.2f}s).",
                )

            return self._failure(
                canary_result,
                "Judge verdict was unparseable. Analysis incomplete; fail-open routing applies.",
            )

        except requests.Timeout:
            logger.warning("Judge timed out after %ss", self.timeout)
            return self._failure(
                canary_result,
                "Judge timed out. Analysis incomplete; fail-open routing applies.",
            )
        except requests.ConnectionError:
            logger.warning(
                "Cannot connect to judge at %s",
                _redacted_origin(self.base_url),
            )
            return self._failure(
                canary_result,
                "Judge unavailable. Analysis incomplete; fail-open routing applies.",
            )
        except Exception as exc:
            logger.warning(
                "OpenAI-compatible judge failed with %s",
                type(exc).__name__,
            )
            return self._failure(
                canary_result,
                "Judge error. Analysis incomplete; fail-open routing applies.",
            )

    def _parse_verdict(self, raw_output: str) -> str | None:
        """
        Parse SAFE/UNSAFE from judge output.
        Handles thinking tags by stripping ``<think>...</think>`` blocks.
        """
        cleaned = re.sub(r"<think>.*?</think>", "", raw_output, flags=re.DOTALL).strip()
        if not cleaned:
            cleaned = raw_output.strip()

        upper = cleaned.upper()
        if upper == "UNSAFE":
            return "UNSAFE"
        if upper == "SAFE":
            return "SAFE"

        logger.warning("Could not parse judge verdict")
        return None

    def is_available(self):
        # type: () -> bool
        """Check if the API endpoint is reachable with valid credentials."""
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            resp = requests.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=5,
            )
            return bool(resp.status_code == 200)
        except Exception:
            return False
