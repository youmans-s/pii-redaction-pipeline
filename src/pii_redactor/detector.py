"""Detect and redact personally identifiable information (PII) in text.

This module is pure Python with no AWS dependencies, so it can be unit
tested locally and reused inside an AWS Lambda function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# Each pattern is intentionally conservative: it is better to miss an edge
# case than to redact ordinary numbers like order IDs or dates.

PATTERNS: Dict[str, re.Pattern] = {
    # SSN: 123-45-6789. Area 000, 666 and 9xx are never issued; group 00 and
    # serial 0000 are invalid.
    "SSN": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # US phone numbers: (215) 555-0123, 215-555-0123, 215.555.0123, +1 215 555 0123
    "PHONE": re.compile(
        r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?!\d)"
    ),
    # 13-16 digit card numbers, optionally separated by spaces or dashes.
    # Candidates are confirmed with the Luhn checksum below.
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,15}\d(?!\d)"),
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
}

# Order matters: card numbers are checked before phones so a 16-digit card
# is not partly matched as a phone number.
DETECTION_ORDER = ["SSN", "CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS"]


def luhn_valid(number: str) -> bool:
    """Return True if the digits in `number` pass the Luhn checksum."""
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "CREDIT_CARD": luhn_valid,
}


@dataclass(frozen=True)
class Finding:
    """One piece of PII found in the text."""

    pii_type: str
    start: int
    end: int
    value: str


def detect(text: str) -> List[Finding]:
    """Find PII in `text`. Overlapping matches keep the first type found."""
    findings: List[Finding] = []
    taken: List[range] = []

    for pii_type in DETECTION_ORDER:
        validator = VALIDATORS.get(pii_type)
        for match in PATTERNS[pii_type].finditer(text):
            value = match.group()
            if validator and not validator(value):
                continue
            span = range(match.start(), match.end())
            if any(span.start < t.stop and t.start < span.stop for t in taken):
                continue
            taken.append(span)
            findings.append(Finding(pii_type, match.start(), match.end(), value))

    return sorted(findings, key=lambda f: f.start)


def _mask(finding: Finding) -> str:
    """Partially hide a value, keeping just enough to be useful for review."""
    value = finding.value
    if finding.pii_type == "EMAIL":
        local, _, domain = value.partition("@")
        return f"{local[0]}***@{domain}"
    if finding.pii_type in {"SSN", "CREDIT_CARD", "PHONE"}:
        digits = [c for c in value if c.isdigit()]
        return "***-" + "".join(digits[-4:])
    return f"[{finding.pii_type}]"


def redact(text: str, mode: str = "redact") -> tuple[str, List[Finding]]:
    """Return (cleaned_text, findings).

    mode="redact" replaces each value with a label such as [SSN].
    mode="mask"   keeps a small, non-sensitive hint such as ***-6789.
    """
    if mode not in {"redact", "mask"}:
        raise ValueError("mode must be 'redact' or 'mask'")

    findings = detect(text)
    pieces: List[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor:finding.start])
        pieces.append(f"[{finding.pii_type}]" if mode == "redact" else _mask(finding))
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces), findings


def summarize(findings: List[Finding]) -> Dict[str, int]:
    """Count findings by type, without storing the sensitive values."""
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.pii_type] = counts.get(finding.pii_type, 0) + 1
    return counts
