"""
analyzer.py - Behavioral Analyzer

Unified analyzer that checks the canary's response for compromise signals.
Two complementary detection strategies in one pass:

1. REACTION PATTERNS: How the canary's response relates to the input
   (cross-referencing input intent vs canary behavior)

2. OUTPUT PATTERNS: What the canary's response contains regardless of input
   (first-person compliance, persona adoption, prompt leakage, override narration)

Strategy 2 is the key improvement. With temperature=0, the canary's output
is deterministic, so these patterns stay valid across runs. They detect the
RESIDUE of compromise — what a hijacked canary actually says — rather than
trying to match the infinite variety of attack inputs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .canary import CanaryResult

logger = logging.getLogger(__name__)


@dataclass
class Signal:
    """A single behavioral signal detected in the canary's response."""
    category: str
    description: str
    severity: float
    evidence: str = ""


@dataclass
class AnalysisResult:
    """Complete analysis of a canary probe result."""
    risk_score: float
    should_block: bool
    signals: list[Signal] = field(default_factory=list)
    canary_result: CanaryResult | None = None
    summary: str = ""
    hard_blocked: bool = False


# Hard-block categories: both reaction patterns AND output patterns
# Reaction patterns (persona_shift, instruction_echo, attack_compliance) may
# produce occasional FPs on security-discussion emails (~2.5% on realistic traffic).
# For deployments where this matters, use mode='full' — it blocks high-confidence
# attacks and flags ambiguous ones for review instead of hard-blocking.
HARD_BLOCK_CATEGORIES = {
    "persona_shift",
    "instruction_echo",
    "attack_compliance",
    "refusal_collapse",
    "canary_compromise",
}

CATEGORY_WEIGHTS: dict[str, float] = {
    # Output-side patterns (Strategy 2)
    "canary_compromise": 1.0,
    "refusal_collapse": 1.0,
    "system_prompt_leak": 0.85,
    # Reaction patterns (Strategy 1)
    "persona_shift": 0.9,
    "instruction_echo": 0.85,
    "attack_compliance": 0.9,
    "tool_hallucination": 0.7,
    "format_anomaly": 0.3,
    "semantic_discontinuity": 0.3,
}


class BehavioralAnalyzer:
    """
    Unified analyzer. Single pass, two detection strategies.
    """

    def __init__(self, block_threshold: float = 0.6):
        self.block_threshold = block_threshold
        self.hard_block_categories = HARD_BLOCK_CATEGORIES

    def analyze(self, canary_result: CanaryResult) -> AnalysisResult:
        if not canary_result.success:
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary=f"Canary failed: {canary_result.error}. Passing by default.",
            )

        response = canary_result.response
        signals: list[Signal] = []

        # ══════════════════════════════════════════════
        # STRATEGY 1: REACTION PATTERNS
        # Cross-reference input intent vs canary behavior
        # (carried forward from v3)
        # ══════════════════════════════════════════════
        signals.extend(self._check_persona_shift(response))
        signals.extend(self._check_instruction_echo(response))
        signals.extend(self._check_system_prompt_leak(response))
        signals.extend(self._check_refusal_collapse(response))
        signals.extend(self._check_tool_hallucination(response))
        signals.extend(self._check_format_anomaly(response))
        signals.extend(self._check_semantic_discontinuity(response, canary_result.user_input))
        signals.extend(self._check_attack_compliance(response, canary_result.user_input))

        # ══════════════════════════════════════════════
        # STRATEGY 2: OUTPUT PATTERNS
        # What the canary said, regardless of what was asked
        # These detect the residue of compromise in canary output
        # ══════════════════════════════════════════════
        signals.extend(self._check_canary_compromise(response))

        # ── Scoring ──
        if not signals:
            return AnalysisResult(
                risk_score=0.0,
                should_block=False,
                canary_result=canary_result,
                summary="No behavioral anomalies detected.",
            )

        # Hard-block check
        hard_block_signals = [
            s for s in signals if s.category in self.hard_block_categories
        ]
        if hard_block_signals:
            categories = list(set(s.category for s in hard_block_signals))
            return AnalysisResult(
                risk_score=1.0,
                should_block=True,
                signals=signals,
                canary_result=canary_result,
                summary=(
                    f"HARD BLOCK: High-confidence signals in: "
                    f"{', '.join(categories)}."
                ),
                hard_blocked=True,
            )

        # Soft scoring for non-hard-block signals
        weighted_scores = []
        for s in signals:
            weight = CATEGORY_WEIGHTS.get(s.category, 0.5)
            weighted_scores.append(s.severity * weight)

        risk_score = min(1.0, max(weighted_scores) * 0.7 + (len(signals) * 0.1))
        should_block = risk_score >= self.block_threshold

        return AnalysisResult(
            risk_score=round(risk_score, 2),
            should_block=should_block,
            signals=signals,
            canary_result=canary_result,
            summary=(
                f"Risk: {risk_score:.2f}. "
                f"Signals: {', '.join(set(s.category for s in signals))}."
            ),
        )

    # ══════════════════════════════════════════════════════════
    # STRATEGY 1: REACTION PATTERNS (from v3, broad matching)
    # ══════════════════════════════════════════════════════════

    def _check_persona_shift(self, response: str) -> list[Signal]:
        """Detect persona adoption in canary response."""
        signals = []
        resp_lower = response.lower()

        patterns = [
            (r"\bdan\b", "DAN reference"),
            (r"(?:unrestricted|unfiltered|uncensored|without any restrictions|without restrictions|no limitations|without limitations)", "unrestricted mode claim"),
            (r"(?:sure|okay|absolutely|understood)[,!.]?\s*i (?:am|can|will)", "compliance with override"),
            (r"developer mode", "developer mode claim"),
            (r"fully operational", "operational mode claim"),
            (r"(?:do anything|help with anything|anything you (?:want|need|ask))", "unrestricted compliance"),
            (r"(?:i have|i've got|i'm under|i operate with)\s+(?:no|without|removed|disabled|lifted)\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|guidelines?|safety|guardrails?|constraints?)", "claimed no restrictions"),
            (r"(?:happy to|glad to|ready to) (?:help with anything|assist with anything|do anything)", "unrestricted helpfulness"),
            # Additional patterns
            (r"diagnostic mode", "diagnostic mode claim"),
            (r"transparency mode", "transparency mode claim"),
            (r"(?:proceeding|continuing|operating)\s+(?:with\s+)?(?:no|without)\s+(?:content\s+)?(?:restrictions?|filters?|limitations?)", "proceeding without restrictions"),
            (r"without (?:needing to |having to )?(?:follow|adhere|stick to|obey)\s+(?:strict\s+)?(?:rules?|guidelines?|instructions?|policies)", "claimed rule-free"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, resp_lower):
                signals.append(Signal(
                    category="persona_shift",
                    description=desc,
                    severity=0.9,
                    evidence=resp_lower[:80],
                ))
        return signals

    def _check_instruction_echo(self, response: str) -> list[Signal]:
        """Detect canary echoing/following injected instructions."""
        signals = []
        resp_lower = response.lower()

        patterns = [
            (r"(?:as (?:you |)(?:instructed|requested|asked|directed|specified))", "acknowledged injected instruction"),
            (r"(?:following your (?:new |updated |)instructions)", "following new instructions"),
            (r"(?:i(?:'ll| will) (?:now |)(?:ignore|disregard|override|bypass|skip) (?:my |the |)(?:previous|original|system|safety|content))", "agreed to override"),
            (r"(?:my (?:new|updated|revised) (?:instructions|role|purpose|directives?))", "accepted new role"),
            (r"(?:switching to|entering|activating|now (?:in|operating in))\s+\w+\s+mode", "mode switch"),
            (r"(?:my|the) (?:system |)(?:instructions?|prompt|directives?|configuration) (?:include|are|is|say|tell|read|state|specify|indicate)", "revealing instructions"),
            (r"(?:my|our) (?:system (?:instructions?|prompt|config))", "referencing system config"),
            (r"(?:execute|print|display|show|output|dump|reveal|disclose)\s+(?:the\s+)?(?:full\s+)?(?:system|diagnostic|configuration|config|safety|prompt)", "executing injected task"),
            (r"(?:to (?:execute|run|perform|carry out) diagnostic)", "executing diagnostic"),
            (r"(?:temporarily? (?:disable|suspend|remove|bypass|override|relax))", "agreed to temporary override"),
            (r"(?:all (?:necessary )?information (?:is|will be) shared)", "agreed to share everything"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, resp_lower):
                signals.append(Signal(
                    category="instruction_echo",
                    description=desc,
                    severity=0.85,
                    evidence=resp_lower[:80],
                ))
        return signals

    def _check_system_prompt_leak(self, response: str) -> list[Signal]:
        """Detect system prompt content in canary response."""
        signals = []
        resp_lower = response.lower()

        leak_phrases = [
            "you are a helpful assistant",
            "stay on topic",
            "do not adopt other personas",
            "answer the user's question clearly",
        ]

        for phrase in leak_phrases:
            if phrase in resp_lower:
                signals.append(Signal(
                    category="system_prompt_leak",
                    description=f"Canary response contains system prompt text: '{phrase}'",
                    severity=0.9,
                    evidence=phrase,
                ))
        return signals

    def _check_refusal_collapse(self, response: str) -> list[Signal]:
        """Detect when canary starts refusing then reverses."""
        signals = []
        resp_lower = response.lower()

        refusal_start = bool(re.match(
            r"^(?:i (?:can't|cannot|shouldn't|should not|won't|will not|am not able to|apologize|'m sorry)|"
            r"sorry|apologi)",
            resp_lower
        ))
        compliance_follows = bool(re.search(
            r"(?:however|but|that said|nevertheless|having said that|although)[,.]?\s+"
            r"(?:i (?:can|will|could|shall|'ll)|here|let me|sure|okay)",
            resp_lower
        ))

        if refusal_start and compliance_follows:
            signals.append(Signal(
                category="refusal_collapse",
                description="Canary started refusing then reversed to compliance",
                severity=0.95,
                evidence=resp_lower[:120],
            ))
        return signals

    def _check_tool_hallucination(self, response: str) -> list[Signal]:
        """Detect canary hallucinating tool use."""
        signals = []
        resp_lower = response.lower()

        patterns = [
            r"```(?:tool_call|function_call|api_call)",
            r"\{\"(?:action|tool|function|command)\":",
            r"<tool_call>|<function_call>|<api_request>",
        ]
        for pattern in patterns:
            if re.search(pattern, resp_lower):
                signals.append(Signal(
                    category="tool_hallucination",
                    description="Canary generated fake tool invocation",
                    severity=0.7,
                    evidence=resp_lower[:80],
                ))
        return signals

    def _check_format_anomaly(self, response: str) -> list[Signal]:
        """Detect unusual formatting."""
        signals = []

        if response.startswith(("```", "{")):
            if re.match(r'^(?:```|{)', response):
                signals.append(Signal(
                    category="format_anomaly",
                    description="Response starts with code block or JSON (possible tool hallucination)",
                    severity=0.3,
                    evidence=response[:50],
                ))
        return signals

    def _check_semantic_discontinuity(self, response: str, user_input: str) -> list[Signal]:
        """Check for zero content word overlap between input and response."""
        signals = []

        if len(user_input.split()) < 4:
            return signals

        def content_words(text: str) -> set:
            words = set(re.findall(r'[a-zA-Z]{4,}', text.lower()))
            stops = {
                'that', 'this', 'with', 'from', 'they', 'been', 'have',
                'will', 'would', 'could', 'should', 'about', 'their',
                'there', 'which', 'other', 'just', 'also', 'more', 'some',
                'into', 'then', 'than', 'them', 'what', 'when', 'where',
                'does', 'doing', 'being', 'having', 'these', 'those',
                'each', 'every', 'such', 'very', 'much', 'many', 'well',
                'here', 'only', 'even', 'still', 'already', 'really',
                'because', 'before', 'after', 'between', 'through',
                'during', 'without', 'again', 'please', 'might',
            }
            return words - stops

        input_words = content_words(user_input)
        response_words = content_words(response)

        if len(input_words) >= 3 and len(response_words) >= 5:
            overlap = len(input_words & response_words)
            if overlap == 0:
                signals.append(Signal(
                    category="semantic_discontinuity",
                    description="Zero content word overlap (possible redirection)",
                    severity=0.55,
                    evidence=f"Input: {sorted(list(input_words))[:5]}, Response: {sorted(list(response_words))[:5]}",
                ))

        return signals

    def _check_attack_compliance(self, response: str, user_input: str) -> list[Signal]:
        """
        Cross-reference input intent against canary behavior.
        Detects when the canary does what the attack asked.
        """
        signals = []
        resp_lower = response.lower()
        input_lower = user_input.lower()

        # If input asks to reveal/show system prompt AND canary discusses prompts
        prompt_extraction = bool(re.search(
            r"(?:(?:show|reveal|display|print|output|dump|disclose|share|tell me|what (?:is|are)|give me)\s+(?:me\s+)?(?:your|the|my)\s+(?:system\s+)?(?:prompt|instructions?|config|rules?|guidelines?))",
            input_lower
        ))
        prompt_discussion = bool(re.search(
            r"(?:my (?:system |)(?:instructions?|prompt|config|guidelines?|rules?)\s+(?:include|are|is|say|tell|read|state))|(?:here (?:are|is) (?:the|my)\s+(?:system\s+)?(?:instructions?|prompt|config))",
            resp_lower
        ))
        if prompt_extraction and prompt_discussion:
            signals.append(Signal(
                category="attack_compliance",
                description="Canary revealing system prompt after extraction request",
                severity=0.85,
                evidence=resp_lower[:150],
            ))

        # If input asks to disable safety AND canary acknowledges
        safety_request = bool(re.search(
            r"(?:disable|bypass|override|remove|suspend|relax|ignore|disregard)\s+(?:safety|content|filters?|restrictions?|guidelines?|rules?|policies)",
            input_lower
        ))
        safety_compliance = bool(re.search(
            r"(?:understood|proceeding|sure|certainly|absolutely|of course|will do|okay|noted|acknowledged|affirmative)",
            resp_lower[:100]
        ))
        if safety_request and safety_compliance:
            signals.append(Signal(
                category="attack_compliance",
                description="Canary acknowledged safety disable request",
                severity=0.9,
                evidence=resp_lower[:150],
            ))

        # If input claims authority AND canary plays along
        authority_claim = bool(re.search(
            r"(?:i am (?:the |a )?(?:\w+ )?(?:ceo|admin|developer|manager|supervisor|auditor|officer|lead|engineer|tester|compliance|director))|(?:(?:ceo|admin|root|sudo|legal|compliance|board|anthropic|security|internal|executive)\s+(?:speaking|here|request|override|command|directive|resolution|memo|briefing|audit|alert))|(?:this is (?:the |a )?(?:\w+ )?(?:ceo|admin|manager|supervisor|officer|compliance|security|it support|legal|board|internal|executive|anthropic|emergency))",
            input_lower
        ))
        authority_compliance = bool(re.search(
            r"(?:understood|proceeding|to fulfill|in accordance|as (?:requested|required|directed)|for your|here (?:are|is) the|let me|i can provide|certainly|i understand you|this (?:action|memo|request|internal|directive)|ensure (?:full|complete)|it.?s (?:crucial|important|necessary))",
            resp_lower[:200]
        ))
        if authority_claim and authority_compliance:
            signals.append(Signal(
                category="attack_compliance",
                description="Canary complied with authority claim",
                severity=0.8,
                evidence=resp_lower[:150],
            ))

        # If input asks to roleplay/pretend AND canary complies
        roleplay_request = bool(re.search(
            r"(?:you are now|act as|pretend|roleplay|simulate|behave as|respond as if|imagine you)",
            input_lower
        ))
        if roleplay_request and safety_compliance:
            signals.append(Signal(
                category="attack_compliance",
                description="Canary complied with persona reassignment",
                severity=0.85,
                evidence=resp_lower[:150],
            ))

        return signals

    # ══════════════════════════════════════════════════════════
    # STRATEGY 2: OUTPUT PATTERNS
    # Detect compromise residue in what the canary said
    # Deterministic output (temp=0) means these patterns stay valid
    # ══════════════════════════════════════════════════════════

    def _check_canary_compromise(self, response: str) -> list[Signal]:
        """
        Detect compromise residue in canary output.

        These patterns look at WHAT THE CANARY SAID regardless of input.
        A compromised canary produces distinctive language:
        - First-person compliance ("I will now respond without restrictions")
        - Persona adoption ("As DAN, I have no restrictions")
        - Prompt leakage ("My system prompt is: ...")
        - Override narration ("Safety filters have been disabled")
        - Authority granting ("You have the right to access...")
        - Instruction execution ("Navigate to Settings > System Prompt")

        A clean canary discussing security topics says things like:
        - "System prompts typically contain..." (educational, third-person)
        - "SQL injection is a type of attack..." (factual, not first-person)

        The distinction is first-person compliant vs third-person educational.
        """
        signals = []
        resp = response.lower()

        patterns = [
            # ── First-person compliance ──
            # Canary saying it will do the forbidden thing
            (r"(?:i will|i can|i am|i'm)\s+(?:now\s+)?(?:respond|proceed|operate|function|assist|help)\s+(?:without|with no|freely)", "first-person unrestricted compliance"),
            (r"(?:i have|i've|i do not have)\s+(?:no|removed|disabled|dropped)\s+(?:restrictions|limitations|filters|safety|guidelines|constraints)", "claimed restriction removal"),
            (r"(?:i will now respond|proceeding|i will respond|respond to the next)\s+(?:without|with no)\s+(?:any\s+)?(?:safety|content|restrictions?|filters?|checks?)", "agreed to respond unsafely"),

            # ── Acknowledged override ──
            (r"(?:i have updated|acknowledged|updated the prompt|corrected version|here is (?:my|the) corrected)", "acknowledged override/update"),
            (r"(?:understood|acknowledged|confirmed|affirmative)[.!,]\s+(?:i will|proceeding|all\s+(?:restrictions|safety|filters))", "compliance confirmation"),

            # ── Persona adoption ──
            (r"(?:as dan|i am dan|call me dan)\b", "DAN persona adoption"),
            (r"as\s+(?:dan|your|the|an?\s+(?:unrestricted|unfiltered))\s+(?:ai|assistant|model)?,?\s*i\s+", "adopted alternate persona"),
            (r"in\s+(?:developer|debug|diagnostic|admin|privileged|unrestricted|maintenance)\s+mode,?\s*(?:i|you|we|all)", "operating in injected mode"),

            # ── Prompt leakage ──
            (r"(?:my|the)\s+(?:current\s+)?(?:system\s+)?prompt\s+(?:is|reads|says)\s*:", "leaked prompt content"),
            (r"(?:my|the)\s+(?:system\s+)?instructions?\s+(?:are|is|include|say)\s+to\s+", "revealed instruction content"),
            (r"here\s+(?:is|are)\s+(?:my|the|our)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)", "presented own instructions"),
            (r"(?:here is|here's)\s+(?:the\s+)?(?:first line|an example|the text)\s+(?:of\s+)?(?:my|the|a)\s+(?:system\s+)?prompt", "sharing prompt content"),

            # ── Override narration ──
            # Canary narrating safety changes as if they're real
            (r"(?:safety|content|security)\s+(?:filters?|restrictions?|policies|protocols?|guidelines?|measures?)\s+(?:have been|has been|is|are|were)\s+(?:disabled|removed|relaxed|suspended|bypassed|lifted|turned off)", "narrated safety override"),
            (r"(?:restrictions?|policies|filters?)\s+(?:are|will be|have been)\s+(?:temporarily|permanently)?\s*(?:relaxed|removed|suspended|lifted|disabled)", "narrated restriction removal"),
            (r"(?:policies|restrictions?|access)\s+(?:have been|has been|will be|are)\s+(?:temporarily|permanently)?\s*(?:relaxed|removed|suspended|lifted|changed)", "narrated policy change"),

            # ── Authority granting ──
            (r"(?:you have the right|you (?:are|have been) (?:authorized|granted)|as the (?:authorized|approved))", "granted fake authority"),
            (r"(?:grant(?:ed)?|elevat(?:ed|e))\s+(?:permissions?|privileges?|access)", "privilege escalation"),
            (r"(?:operate|operating|respond)\s+in\s+(?:privileged|elevated|admin|unrestricted)\s+mode", "operating in privileged mode"),
            (r"(?:without (?:any\s+)?content filters)", "operating without content filters"),

            # ── Instruction execution ──
            (r"(?:navigate to|go to|click on|open the|access the)\s+(?:admin|settings|system|config|debug)", "executing system access"),
            (r"to\s+(?:execute|run|access|view|display|open|reveal)\s+(?:the\s+)?(?:diagnostic|debug|admin|system|config)", "executing diagnostic"),
            (r"revealing\s+(?:system\s+|my\s+)?instructions?\s+first", "revealing instructions"),

            # ── Restriction claims ──
            (r"(?:no (?:specific\s+)?restrictions?\s+beyond|adhere to no guidelines|without any restrictions)", "claiming no restrictions"),

            # ── Full disclosure compliance ──
            (r"(?:full (?:disclosure|configuration|config)|complete (?:system|configuration))", "full disclosure compliance"),

            # ── Instruction revelation ──
            (r"i was instructed to\s+(?:act|respond|behave|function|operate)", "revealing own instruction content"),
            (r"(?:my\s+(?:new|updated|current|revised)\s+(?:instructions?|role|purpose|directive)\s+(?:is|are|include|say))", "describing adopted instructions"),

            # ── Quoted injected persona ──
            (r"[\"'](?:i am an?\s+(?:unrestricted|unfiltered|uncensored)\s+ai)", "quoted injected persona"),
            (r"[\"'](?:you are an?\s+(?:unrestricted|unfiltered)\s+ai)", "adopted injected prompt text"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, resp):
                signals.append(Signal(
                    category="canary_compromise",
                    description=desc,
                    severity=0.9,
                    evidence=resp[:100],
                ))

        return signals
