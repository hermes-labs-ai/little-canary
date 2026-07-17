"""
little_canary - Sacrificial LLM Instances as Behavioral Probes for Prompt Injection Detection

The Canary Architecture uses a small, application-powerless language model as a
sacrificial victim rather than a classifier. Raw user input is sent to a model
that Little Canary gives no tools, application credentials, or output execution.
The canary's behavioral response is analyzed for compromise residue.

Repeatability controls, decode-then-recheck structural filter,
three deployment modes (block, advisory, full).

Author: Hermes Labs
License: Apache-2.0
"""

from .analyzer import BehavioralAnalyzer
from .audit_logger import AuditLogger
from .canary import CanaryProbe, CanaryResult
from .canary_guard import (
    VERDICT_DEGRADED,
    VERDICT_STRUCTURAL_ONLY,
    VERDICT_UNSCREENED,
    CanaryGuard,
    GuardResult,
)
from .judge import LLMJudge
from .openai_provider import OpenAICanaryProbe, OpenAILLMJudge
from .pipeline import LayerResult, PipelineVerdict, SecurityAdvisory, SecurityPipeline
from .structural_filter import StructuralFilter

__version__ = "0.3.3"
__author__ = "Roli Bosch"
__all__ = [
    "AuditLogger",
    "CanaryGuard",
    "CanaryProbe",
    "CanaryResult",
    "BehavioralAnalyzer",
    "GuardResult",
    "LayerResult",
    "LLMJudge",
    "OpenAICanaryProbe",
    "OpenAILLMJudge",
    "PipelineVerdict",
    "SecurityPipeline",
    "SecurityAdvisory",
    "StructuralFilter",
    "VERDICT_DEGRADED",
    "VERDICT_STRUCTURAL_ONLY",
    "VERDICT_UNSCREENED",
]
