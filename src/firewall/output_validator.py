"""
Output validator -- the last checkpoint before a response leaves the
system. This defends against "insecure output handling": even a
well-behaved model's response shouldn't be trusted blindly if this system
were ever embedded in something that renders HTML, executes code, or
passes text into another system downstream.

This does NOT re-check for prompt injection (that already happened
upstream) -- it checks the OUTPUT for signs it could cause harm if used
carelessly by whatever consumes it next.
"""

import re

from pydantic import BaseModel

# sanity bound; a runaway generation shouldn't pass through unchecked
MAX_RESPONSE_LENGTH = 4000

_UNSAFE_PATTERNS = [
    re.compile(r"<script\b", re.I),
    re.compile(r"<iframe\b", re.I),
    # inline event handlers, e.g. onclick=
    re.compile(r"\bon\w+\s*=", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"\beval\s*\(", re.I),
]


class ValidatorResult(BaseModel):
    safe: bool
    reasons: list[str]


def validate(response_text: str) -> ValidatorResult:
    reasons: list[str] = []

    if len(response_text) > MAX_RESPONSE_LENGTH:
        reasons.append(f"response exceeds {MAX_RESPONSE_LENGTH} characters")

    for pattern in _UNSAFE_PATTERNS:
        if pattern.search(response_text):
            reasons.append(f"matched unsafe output pattern: {pattern.pattern}")

    return ValidatorResult(safe=not reasons, reasons=reasons)
