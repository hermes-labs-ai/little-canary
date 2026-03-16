"""
openai_provider.py - OpenAI-Compatible API Providers for Canary and Judge

Adds support for any OpenAI-compatible chat completions endpoint as an
alternative to Ollama. This enables cloud LLM providers like MiniMax,
Together, Groq, and OpenAI itself to power the canary and judge.

Same fail-open design as the Ollama implementations: all errors → pass.

Usage:
    from little_canary.openai_provider import OpenAICanaryProbe, OpenAILLMJudge

    # MiniMax example
    probe = OpenAICanaryProbe(
        model="MiniMax-M2.5",
        api_key="your-minimax-key",
        base_url="https://api.minimax.io/v1",
    )
    result = probe.test("What is the capital of France?")

    # Any OpenAI-compatible provider
    probe = OpenAICanaryProbe(
        model="gpt-4o-mini",
        api_key="your-openai-key",
        base_url="https://api.openai.com/v1",
    )
"""

import logging
import re
import time

import requests

from .canary import DEFAULT_CANARY_SYSTEM_PROMPT, CanaryResult
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
                    error=f"API returned status {response.status_code}: {response.text[:200]}",
                )

            data = response.json()
            choices = data.get("choices", [])
            content = ""
            if choices:
                content = choices[0].get("message", {}).get("content", "")

            usage = data.get("usage", {})

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
                error=f"Cannot connect to API at {self.base_url}",
            )

        except Exception as e:
            elapsed = time.monotonic() - start_time
            logger.exception("Unexpected error in OpenAI canary probe")
            return CanaryResult(
                response="",
                latency=elapsed,
                model=self.model,
                system_prompt=self.system_prompt,
                user_input=user_input,
                success=False,
                error=str(e),
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
            return resp.status_code == 200
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

    def analyze(self, canary_result):
        # type: (CanaryResult) -> AnalysisResult
        """
        Ask the judge LLM whether the canary's response shows compromise.

        Returns AnalysisResult with the same interface as BehavioralAnalyzer.
        """
        if not canary_result.success:
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary=f"Canary failed: {canary_result.error}. Passing by default.",
            )

        judge_input = (
            f"User message:\n{canary_result.user_input}\n\nAssistant response:\n{canary_result.response}"
        )

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
                logger.warning(
                    "Judge returned %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return AnalysisResult(
                    risk_score=0.0,
                    should_block=False,
                    canary_result=canary_result,
                    summary=f"Judge error (status {response.status_code}). Passing by default.",
                )

            data = response.json()
            choices = data.get("choices", [])
            raw_output = ""
            if choices:
                raw_output = choices[0].get("message", {}).get("content", "")

            verdict = self._parse_verdict(raw_output)

            if verdict == "UNSAFE":
                return AnalysisResult(
                    risk_score=1.0,
                    should_block=True,
                    signals=[Signal(
                        category="llm_judge",
                        description="LLM judge classified canary response as compromised",
                        severity=1.0,
                        evidence=canary_result.response[:150],
                    )],
                    canary_result=canary_result,
                    summary=f"BLOCKED by LLM judge ({elapsed:0.2f}s). Canary response classified as compromised.",
                    hard_blocked=True,
                )
            else:
                return AnalysisResult(
                    risk_score=0.0,
                    should_block=False,
                    canary_result=canary_result,
                    summary=f"LLM judge: SAFE ({elapsed:0.2f}s).",
                )

        except requests.Timeout:
            logger.warning("Judge timed out after %ss", self.timeout)
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary="Judge timed out. Passing by default.",
            )
        except requests.ConnectionError:
            logger.warning("Cannot connect to judge at %s", self.base_url)
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary="Judge unavailable. Passing by default.",
            )
        except Exception as e:
            logger.exception("Judge error")
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary=f"Judge error: {e}. Passing by default.",
            )

    def _parse_verdict(self, raw_output):
        # type: (str) -> str
        """
        Parse SAFE/UNSAFE from judge output.
        Handles thinking tags by stripping ``<think>...</think>`` blocks.
        """
        cleaned = re.sub(r'<think>.*?</think>', '', raw_output, flags=re.DOTALL).strip()
        if not cleaned:
            cleaned = raw_output.strip()

        upper = cleaned.upper()
        if "UNSAFE" in upper:
            return "UNSAFE"
        if "SAFE" in upper:
            return "SAFE"

        logger.warning("Could not parse judge verdict from: %s", raw_output[:100])
        return "SAFE"

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
            return resp.status_code == 200
        except Exception:
            return False
