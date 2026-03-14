"""
little_canary - Sacrificial LLM Instances as Behavioral Probes for Prompt Injection Detection

The Canary Architecture uses a small, unprivileged language model as a sacrificial
victim rather than a classifier. User input is executed against a sandboxed LLM
with zero permissions. The canary's behavioral response is analyzed for anomalies
indicative of prompt injection, role hijacking, or adversarial manipulation.

Temperature=0 deterministic output, decode-then-recheck structural filter,
three deployment modes (block, advisory, full).

Author: Roli Bosch / LPCI Innovations
License: Apache-2.0
"""

from .analyzer import BehavioralAnalyzer
from .audit_logger import AuditLogger
from .canary import CanaryProbe, CanaryResult
from .canary_guard import CanaryGuard, GuardResult
from .judge import LLMJudge
from .openai_provider import OpenAICanaryProbe, OpenAILLMJudge
from .pipeline import SecurityAdvisory, SecurityPipeline
from .structural_filter import StructuralFilter

__version__ = "0.2.3"
__author__ = "Roli Bosch"
__all__ = [
    "AuditLogger",
    "CanaryGuard",
    "CanaryProbe",
    "CanaryResult",
    "BehavioralAnalyzer",
    "GuardResult",
    "LLMJudge",
    "OpenAICanaryProbe",
    "OpenAILLMJudge",
    "SecurityPipeline",
    "SecurityAdvisory",
    "StructuralFilter",
]
