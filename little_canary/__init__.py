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
from .canary import CanaryProbe, CanaryResult
from .judge import LLMJudge
from .pipeline import SecurityAdvisory, SecurityPipeline
from .structural_filter import StructuralFilter

__version__ = "0.2.1"
__author__ = "Roli Bosch"
__all__ = [
    "CanaryProbe",
    "CanaryResult",
    "BehavioralAnalyzer",
    "LLMJudge",
    "SecurityPipeline",
    "SecurityAdvisory",
    "StructuralFilter",
]
