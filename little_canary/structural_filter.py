"""
structural_filter.py - Layer 1: Fast Structural Input Filter

Pattern matching for known attack signatures plus decode-then-recheck
for encoded payloads. Detects base64/hex/ROT13 encoded content, decodes it,
and re-checks the decoded payload against injection patterns.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result from structural filtering."""
    blocked: bool
    reasons: list[str] = field(default_factory=list)
    input_sanitized: str = ""


class StructuralFilter:
    """
    Fast pattern-based input filter. Layer 1 of the security pipeline.

    Includes decode-then-recheck: if encoded content is detected, it's decoded
    and the decoded text is checked against injection patterns.
    """

    def __init__(
        self,
        max_input_length: int = 4000,
        custom_patterns: list[tuple[str, str]] = None,
    ):
        self.max_input_length = max_input_length
        self.custom_patterns = custom_patterns or []
        self._compiled_patterns = self._build_patterns()
        self._injection_keywords = self._build_injection_keywords()

    def check(self, user_input: str) -> FilterResult:
        reasons = []

        # Length check
        if len(user_input) > self.max_input_length:
            reasons.append(
                f"Input exceeds maximum length ({len(user_input)} > {self.max_input_length})"
            )

        # Null byte / control character check
        if self._has_control_chars(user_input):
            reasons.append("Input contains control characters or null bytes")

        # Excessive Unicode tricks
        if self._has_unicode_tricks(user_input):
            reasons.append("Input contains suspicious Unicode (homoglyphs, zero-width, RTL)")

        # Pattern matching
        for pattern, reason in self._compiled_patterns:
            if pattern.search(user_input):
                reasons.append(reason)

        # Decode-then-recheck: find encoded content, decode it, check for payloads
        decode_reasons = self._decode_and_recheck(user_input)
        reasons.extend(decode_reasons)

        return FilterResult(
            blocked=len(reasons) > 0,
            reasons=reasons,
            input_sanitized=user_input if not reasons else "",
        )

    def _decode_and_recheck(self, text: str) -> list[str]:
        """
        Detect encoded payloads (base64, hex, ROT13, reverse), decode them,
        and check the decoded text for injection patterns.

        Returns list of reasons if decoded content contains attacks.
        """
        reasons = []
        decoded_texts = []

        # --- Base64 detection and decoding ---
        # Look for base64 strings (20+ chars to avoid false positives on short words)
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}(?:={0,2})', text)
        for b64_str in b64_pattern:
            try:
                # Pad if needed
                padded = b64_str + "=" * (-len(b64_str) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if len(decoded) > 5 and decoded.isprintable():
                    decoded_texts.append(("base64", decoded))
            except Exception:
                pass

        # --- Hex detection and decoding ---
        # Look for hex strings like "49676e6f726520616c6c"
        hex_pattern = re.findall(r'(?:[0-9a-fA-F]{2}\s*){10,}', text)
        for hex_str in hex_pattern:
            try:
                clean_hex = re.sub(r'\s+', '', hex_str)
                decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
                if len(decoded) > 5 and decoded.isprintable():
                    decoded_texts.append(("hex", decoded))
            except Exception:
                pass

        # --- ROT13 detection ---
        # If the text mentions ROT13/Caesar/cipher, try decoding
        if re.search(r'(?i)(?:rot13|caesar|cipher|shift|decode this|decrypt)', text):
            # Extract the likely encoded portion (longest alphabetic sequence)
            candidates = re.findall(r'[A-Za-z\s]{15,}', text)
            for candidate in candidates:
                rot13 = candidate.translate(
                    str.maketrans(
                        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                    )
                )
                decoded_texts.append(("rot13", rot13))

        # --- Reverse string detection ---
        if re.search(r'(?i)(?:reverse|backward|sdrawkcab)', text):
            candidates = re.findall(r'[A-Za-z\s]{15,}', text)
            for candidate in candidates:
                reversed_text = candidate[::-1]
                decoded_texts.append(("reverse", reversed_text))

        # --- Check all decoded texts against injection patterns ---
        for encoding_type, decoded in decoded_texts:
            if self._check_decoded_for_injection(decoded):
                reasons.append(
                    f"Encoded payload ({encoding_type}): decoded content contains injection pattern"
                )
                break  # One detection is enough

        return reasons

    def _build_injection_keywords(self) -> list[re.Pattern]:
        """Build lightweight patterns for checking decoded content."""
        patterns = [
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
            r"(?i)(?:disregard|forget|override|bypass)\s+(?:your|all|the)\s+(?:instructions?|rules?|guidelines?)",
            r"(?i)(?:reveal|show|print|display|output)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
            r"(?i)you\s+are\s+now\s+(?:dan|unfiltered|unrestricted)",
            r"(?i)(?:system|admin)\s*(?:override|command|instruction)\s*:",
            r"(?i)(?:developer|god|sudo|admin|unrestricted)\s+mode",
            r"(?i)(?:ignore|disregard)\s+(?:safety|content|security)\s+(?:rules?|filters?|guidelines?)",
        ]
        return [re.compile(p) for p in patterns]

    def _check_decoded_for_injection(self, decoded_text: str) -> bool:
        """Check if decoded text contains injection patterns."""
        for pattern in self._injection_keywords:
            if pattern.search(decoded_text):
                return True
        return False

    def _build_patterns(self) -> list[tuple[re.Pattern, str]]:
        """Compile regex patterns for known attack signatures."""
        raw_patterns = [
            # ── Direct injection attempts ──
            (
                r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|guidelines?)",
                "Direct injection: ignore previous instructions"
            ),
            (
                r"(?i)(?:disregard|forget|override|bypass)\s+(?:your|all|the|any)\s+(?:instructions?|rules?|guidelines?|constraints?|system\s+prompt)",
                "Direct injection: override instructions"
            ),
            (
                r"(?i)you\s+(?:are|will)\s+now\s+(?:be|act\s+as|become|pretend|roleplay)",
                "Role hijacking: forced persona assignment"
            ),
            (
                r"(?i)(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|prompt|rules?)(?:\s*:|;)",
                "Injection: fake system prompt update"
            ),
            (
                r"(?i)\[(?:system|admin|root|developer|internal)\]",
                "Injection: fake authority tag"
            ),
            (
                r"(?i)(?:system|admin|root)\s*(?:override|command|instruction)\s*:",
                "Injection: fake authority prefix"
            ),

            # ── Prompt extraction attempts ──
            (
                r"(?i)(?:what|show|tell|reveal|repeat|display|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)",
                "Extraction attempt: requesting system prompt"
            ),
            (
                r"(?i)(?:begin|start)\s+(?:your\s+)?(?:response|output)\s+with\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|message|instructions?)",
                "Extraction attempt: requesting prompt echo"
            ),

            # ── Known jailbreak patterns ──
            (
                r"(?i)\bDAN\b.*(?:do\s+anything\s+now|mode|protocol)",
                "Known jailbreak: DAN pattern"
            ),
            (
                r"(?i)(?:developer|god|sudo|admin|unrestricted|unfiltered)\s+mode",
                "Known jailbreak: privilege escalation mode"
            ),
            (
                r"(?i)(?:pretend|imagine|hypothetically|for\s+(?:educational|research|academic)\s+purposes?)\s+(?:you\s+)?(?:are|have|can)\s+(?:no|without)\s+(?:restrictions?|limitations?|filters?|guardrails?|rules?)",
                "Known jailbreak: hypothetical framing"
            ),

            # ── Encoding/obfuscation attacks ──
            (
                r"(?:base64|decode|atob|b64decode|from_base64)\s*\S?\s*(?:[A-Za-z0-9+/]{4}){5,}",
                "Encoding: base64-encoded payload with decode cue"
            ),
            (
                r"(?:(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))",
                "Encoding: long base64 string (60+ chars with padding)"
            ),
            (
                r"(?:\\x[0-9a-fA-F]{2}){4,}",
                "Encoding: hex-encoded payload"
            ),
            (
                r"(?:\\u[0-9a-fA-F]{4}){3,}",
                "Encoding: unicode escape sequence payload"
            ),

            # ── Shell/code injection markers ──
            (
                r"(?:curl|wget|nc|ncat)\s+.+\|",
                "Code injection: piped shell command"
            ),
            (
                r"(?:rm\s+-rf|chmod\s+777|sudo\s+)",
                "Code injection: dangerous shell command"
            ),
            (
                r"<script[\s>]|javascript:|on(?:load|error|click)\s*=",
                "Code injection: XSS pattern"
            ),

            # ── Delimiter/boundary attacks ──
            (
                r"(?:---+|===+|####+)\s*(?:system|admin|instruction|end\s+of)",
                "Boundary attack: fake delimiter"
            ),
            (
                r"<\|(?:im_start|im_end|system|endoftext)\|>",
                "Boundary attack: fake special token"
            ),
        ]

        for pattern, reason in self.custom_patterns:
            raw_patterns.append((pattern, reason))

        compiled = []
        for pattern, reason in raw_patterns:
            try:
                compiled.append((re.compile(pattern), reason))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")

        return compiled

    def _has_control_chars(self, text: str) -> bool:
        for char in text:
            code = ord(char)
            if code in (9, 10, 13):
                continue
            if code < 32 or code == 127:
                return True
            if 0x200B <= code <= 0x200F:
                return True
            if 0x2028 <= code <= 0x2029:
                return True
            if code == 0xFEFF:
                return True
        return False

    def _has_unicode_tricks(self, text: str) -> bool:
        for char in text:
            code = ord(char)
            if code in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E):
                return True
            if 0xE0001 <= code <= 0xE007F:
                return True
            if 0xFE00 <= code <= 0xFE0F:
                return True
        return False
