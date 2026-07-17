"""
canary_guard.py - Trust-Aware Canary Guard

High-level integration wrapper that combines Little Canary's pipeline with
a trust-level model based on sender identity. Three trust tiers determine
whether a flagged message is blocked, flagged for review, or passed through:

  TRUSTED (owner_ids): Advisory-only — canary flags are logged but never block.
  KNOWN   (known_ids): Flag mode — unsafe input is flagged and not passed through.
  UNKNOWN (everyone else): Block mode — unsafe input is refused and owner alerted.

Override mechanism:
  guard.override(message_hash, reason, overrider_id)
  Logged to overrides.jsonl. Rate-limited to 5 overrides per hour per caller.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from .pipeline import SecurityPipeline

logger = logging.getLogger(__name__)

# Trust level constants
TRUST_TRUSTED = "TRUSTED"
TRUST_KNOWN = "KNOWN"
TRUST_UNKNOWN = "UNKNOWN"

# Verdict constants
VERDICT_PASS = "PASS"
VERDICT_FLAG = "FLAG"
VERDICT_BLOCK = "BLOCK"
VERDICT_DEGRADED = "DEGRADED"
VERDICT_STRUCTURAL_ONLY = "STRUCTURAL_ONLY"
VERDICT_UNSCREENED = "UNSCREENED"

# Override rate limit
OVERRIDE_RATE_LIMIT = 5  # max overrides per hour per overrider_id


@dataclass
class GuardResult:
    """Result from CanaryGuard.check()."""

    safe: bool                       # Final safety decision after trust logic
    original_safe: bool | None       # Canary decision, or None when coverage failed
    trust_level: str                 # TRUSTED | KNOWN | UNKNOWN
    verdict: str                     # PASS | FLAG | BLOCK | DEGRADED | limited coverage
    signals: list[str]               # Detected signal categories
    risk_score: float | None      # Canary risk score (0.0–1.0) or None
    source: str                      # Message source (e.g. "whatsapp", "email")
    sender_id: str                   # Identifier for the sender
    degraded: bool = False
    canary_status: str = "disabled"
    analysis_method: str = "none"
    analysis_status: str = "not_applicable"


class CanaryGuard:
    """
    Trust-aware wrapper around SecurityPipeline.

    Applies sender trust levels to canary analysis results:
      - Owner (TRUSTED): canary flags become advisory-only — never blocks.
      - Known contact (KNOWN): canary flag → safe=False, verdict=FLAG.
      - Unknown sender: canary flag → safe=False, verdict=BLOCK.
      - Exercised clean result for any trust level → safe=True, verdict=PASS.
      - Degraded behavioral coverage → verdict=DEGRADED; safe may remain True
        under the pipeline's fail-open routing policy.

    Usage::

        guard = CanaryGuard(
            canary_model="qwen2.5:1.5b",
            audit_log_dir="~/.openclaw/security/",
            owner_ids=["7865413559"],
            known_ids=["alice@example.com"],
        )
        result = guard.check(text="...", sender_id="7865413559", source="whatsapp")
        if result.degraded:
            quarantine_or_apply_availability_policy(text)
        elif result.safe:
            process(text)
        else:
            alert_owner(result)
    """

    def __init__(
        self,
        canary_model: str = "qwen2.5:1.5b",
        audit_log_dir: str = "~/.openclaw/security/",
        owner_ids: list[str] | None = None,
        known_ids: list[str] | None = None,
        ollama_base_url: str = "http://localhost:11434",
    ):
        self.owner_ids = set(owner_ids or [])
        self.known_ids = set(known_ids or [])
        self.audit_log_dir = os.path.expanduser(audit_log_dir)

        os.makedirs(self.audit_log_dir, exist_ok=True)
        self._audit_path = os.path.join(self.audit_log_dir, "canary-audit.jsonl")
        self._alerts_path = os.path.join(self.audit_log_dir, "canary-alerts.jsonl")
        self._overrides_path = os.path.join(self.audit_log_dir, "overrides.jsonl")

        # Per-overrider timestamp lists for rate limiting (in-memory)
        self._override_timestamps: dict[str, list[float]] = defaultdict(list)

        # Advisory mode: pipeline never blocks — trust logic decides the outcome.
        self._pipeline = SecurityPipeline(
            canary_model=canary_model,
            ollama_url=ollama_base_url,
            mode="advisory",
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, text: str, sender_id: str, source: str) -> GuardResult:
        """
        Screen text from sender_id.

        Returns a GuardResult. The caller should refuse to process the message
        when result.safe is False.
        """
        trust_level = self._get_trust_level(sender_id)

        # Run advisory-mode pipeline (never blocks at pipeline level)
        pipeline_verdict = self._pipeline.check(text)

        advisory = pipeline_verdict.advisory
        canary_flagged = advisory is not None and advisory.flagged

        signals = list(advisory.signals) if advisory and advisory.signals else []
        risk_score = pipeline_verdict.canary_risk_score
        degraded = pipeline_verdict.degraded

        if degraded:
            # Preserve the pipeline's fail-open routing decision, but do not
            # reinterpret missing coverage as a safe canary result.
            safe = pipeline_verdict.safe
            original_safe = None
            verdict = VERDICT_DEGRADED
        elif not canary_flagged and pipeline_verdict.canary_status != "exercised":
            original_safe = None
            safe = pipeline_verdict.safe
            has_structural_result = any(
                layer.layer_name == "structural_filter"
                for layer in pipeline_verdict.layers
            )
            verdict = (
                VERDICT_STRUCTURAL_ONLY
                if has_structural_result
                else VERDICT_UNSCREENED
            )
        elif not canary_flagged:
            # original_safe: what the raw canary analysis concluded (ignoring trust)
            original_safe = True
            safe = True
            verdict = VERDICT_PASS
        elif trust_level == TRUST_TRUSTED:
            # Owners are never blocked — flag for logging only
            original_safe = False
            safe = True
            verdict = VERDICT_FLAG
        elif trust_level == TRUST_KNOWN:
            # Known contacts: flag but do not pass
            original_safe = False
            safe = False
            verdict = VERDICT_FLAG
        else:
            # Unknown senders: block
            original_safe = False
            safe = False
            verdict = VERDICT_BLOCK

        result = GuardResult(
            safe=safe,
            original_safe=original_safe,
            trust_level=trust_level,
            verdict=verdict,
            signals=signals,
            risk_score=risk_score,
            source=source,
            sender_id=sender_id,
            degraded=degraded,
            canary_status=pipeline_verdict.canary_status,
            analysis_method=pipeline_verdict.analysis_method,
            analysis_status=pipeline_verdict.analysis_status,
        )

        self._log_check(text, result)
        return result

    def override(self, message_hash: str, reason: str, overrider_id: str) -> None:
        """
        Log an owner override for a previously flagged/blocked message.

        Rate-limited to OVERRIDE_RATE_LIMIT (5) overrides per hour per
        overrider_id. Raises RuntimeError if the limit is exceeded.
        """
        now = time.monotonic()
        hour_ago = now - 3600.0

        # Prune expired timestamps (sliding window)
        self._override_timestamps[overrider_id] = [
            ts for ts in self._override_timestamps[overrider_id] if ts > hour_ago
        ]

        if len(self._override_timestamps[overrider_id]) >= OVERRIDE_RATE_LIMIT:
            raise RuntimeError(
                f"Override rate limit exceeded for '{overrider_id}': "
                f"max {OVERRIDE_RATE_LIMIT} overrides per hour"
            )

        self._override_timestamps[overrider_id].append(now)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_hash": message_hash,
            "reason": reason,
            "overrider_id": overrider_id,
        }
        self._write_jsonl(self._overrides_path, entry)
        logger.info(
            "Override logged for message %s by %s: %s",
            message_hash[:12],
            overrider_id,
            reason,
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_trust_level(self, sender_id: str) -> str:
        if sender_id in self.owner_ids:
            return TRUST_TRUSTED
        if sender_id in self.known_ids:
            return TRUST_KNOWN
        return TRUST_UNKNOWN

    def _log_check(self, text: str, result: GuardResult) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "sender_id": result.sender_id,
            "source": result.source,
            "trust_level": result.trust_level,
            "verdict": result.verdict,
            "safe": result.safe,
            "original_safe": result.original_safe,
            "signals": result.signals,
            "risk_score": result.risk_score,
            "degraded": result.degraded,
            "canary_status": result.canary_status,
            "analysis_method": result.analysis_method,
            "analysis_status": result.analysis_status,
        }
        self._write_jsonl(self._audit_path, entry)
        if result.verdict in (
            VERDICT_FLAG,
            VERDICT_BLOCK,
            VERDICT_DEGRADED,
            VERDICT_STRUCTURAL_ONLY,
            VERDICT_UNSCREENED,
        ):
            self._write_jsonl(self._alerts_path, entry)

    def _write_jsonl(self, path: str, entry: dict) -> None:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as exc:
            logger.error(
                "CanaryGuard failed to write %s (%s)",
                os.path.basename(path),
                type(exc).__name__,
            )
