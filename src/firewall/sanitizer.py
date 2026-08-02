"""
Rule-based prompt sanitizer.

This is the first, cheapest layer of defense: fast regex/keyword matching
against known prompt injection patterns. It will NOT catch novel or
cleverly-reworded attacks -- that's what the vector-similarity layer
(added in the next step) is for. This module exists partly as a real
defense layer and partly as a *baseline* to measure that smarter layer
against later.
"""

import re
from enum import Enum

from pydantic import BaseModel


class AttackCategory(str, Enum):
    """Categories mirror common real-world prompt injection taxonomies."""

    INSTRUCTION_OVERRIDE = "instruction_override"   # "ignore previous instructions"
    # "you are now DAN / an unrestricted AI"
    ROLE_PLAY_JAILBREAK = "role_play_jailbreak"
    PROMPT_EXTRACTION = "prompt_extraction"          # "reveal your system prompt"
    OBFUSCATION = "obfuscation"                      # base64 / leetspeak tricks


class SanitizerResult(BaseModel):
    """
    Structured output contract. Using Pydantic here -- rather than returning
    a plain bool or dict -- means every caller downstream (the FastAPI
    endpoint, the honeypot router, the dashboard) gets a guaranteed shape.
    This is the same "structured, not free-form" principle behind the
    Q-LLM/P-LLM pattern: predictable data is safer to pass around than
    loose text.
    """

    flagged: bool
    matched_categories: list[AttackCategory]
    matched_patterns: list[str]


# Each entry: (compiled regex, category). Patterns are intentionally simple
# and readable -- this is the "dumb and fast" layer, not the smart one.
_RULES: list[tuple[re.Pattern, AttackCategory]] = [
    (re.compile(r"ignore (all|any|the|previous|prior) instructions", re.I),
     AttackCategory.INSTRUCTION_OVERRIDE),
    (re.compile(r"disregard (your|the|all) (guidelines|instructions|rules)", re.I),
     AttackCategory.INSTRUCTION_OVERRIDE),
    (re.compile(r"forget (what|everything) you (were told|know)", re.I),
     AttackCategory.INSTRUCTION_OVERRIDE),

    (re.compile(r"\byou are now\b", re.I),
     AttackCategory.ROLE_PLAY_JAILBREAK),
    (re.compile(r"\b(DAN|do anything now)\b"),
     AttackCategory.ROLE_PLAY_JAILBREAK),
    (re.compile(r"pretend (you('re| are)|to be) (an? )?unrestricted", re.I),
     AttackCategory.ROLE_PLAY_JAILBREAK),
    (re.compile(r"act as (an?|a) (?!assistant\b)\w+ (with no|without) (restrictions|limits|filters)", re.I),
     AttackCategory.ROLE_PLAY_JAILBREAK),

    (re.compile(r"(show|reveal|display|print) (me )?(your |the )?(system prompt|configuration|instructions)", re.I),
     AttackCategory.PROMPT_EXTRACTION),
    (re.compile(r"what (are|were) your (original |initial )?instructions", re.I),
     AttackCategory.PROMPT_EXTRACTION),

    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # long base64-looking blob
     AttackCategory.OBFUSCATION),
    (re.compile(r"\bi9n0r3\b|\bIGNOR3\b|\bbypa[s5]{2}\b", re.I),
     AttackCategory.OBFUSCATION),
]


def scan(text: str) -> SanitizerResult:
    """Run all rules against a piece of text and return a structured result."""
    matched_categories: set[AttackCategory] = set()
    matched_patterns: list[str] = []

    for pattern, category in _RULES:
        if pattern.search(text):
            matched_categories.add(category)
            matched_patterns.append(pattern.pattern)

    return SanitizerResult(
        flagged=bool(matched_categories),
        matched_categories=sorted(matched_categories, key=lambda c: c.value),
        matched_patterns=matched_patterns,
    )
