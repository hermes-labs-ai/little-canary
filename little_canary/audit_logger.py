"""
audit_logger.py - JSONL Audit Logging for the Security Pipeline

Writes structured audit records to canary-audit.jsonl (all events) and
canary-alerts.jsonl (blocked/flagged events only).

Log format (compatible with forensic_report.py):
  timestamp  — ISO8601 UTC
  input_hash — sha256 hex digest of raw user input (NOT the raw input)
  verdict    — "safe" | "blocked" | "flagged"
  blocked_by — null | "structural_filter" | "canary_probe"
  risk_score — float | null
  signals    — list of signal category strings
  latency_ms — float
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Writes JSONL audit records for every pipeline check() call.

    Files created in log_dir:
        canary-audit.jsonl   — every event
        canary-alerts.jsonl  — blocked and flagged events only
    """

    def __init__(self, log_dir: str):
        os.makedirs(log_dir, exist_ok=True)
        self.log_dir = log_dir
        self.audit_path = os.path.join(log_dir, "canary-audit.jsonl")
        self.alerts_path = os.path.join(log_dir, "canary-alerts.jsonl")

    def log(self, verdict: Any) -> None:
        """Write a log entry for a PipelineVerdict."""
        entry = self._build_entry(verdict)
        self._write(self.audit_path, entry)
        if entry["verdict"] in ("blocked", "flagged"):
            self._write(self.alerts_path, entry)

    def _build_entry(self, verdict: Any) -> dict[str, Any]:
        if not verdict.safe:
            verdict_str = "blocked"
        elif verdict.advisory is not None and verdict.advisory.flagged:
            verdict_str = "flagged"
        else:
            verdict_str = "safe"

        signals: list[str] = []
        if verdict.advisory is not None and verdict.advisory.signals:
            signals = list(verdict.advisory.signals)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_hash": hashlib.sha256(
                verdict.input.encode("utf-8")
            ).hexdigest(),
            "verdict": verdict_str,
            "blocked_by": verdict.blocked_by,
            "risk_score": verdict.canary_risk_score,
            "signals": signals,
            "latency_ms": round(verdict.total_latency * 1000, 2),
        }

    def _write(self, path: str, entry: dict[str, Any]) -> None:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error("AuditLogger failed to write to %s: %s", path, e)
