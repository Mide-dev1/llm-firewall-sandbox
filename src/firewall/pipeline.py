"""
Combines the rule-based sanitizer and the vector-similarity filter into a
single detection decision. A prompt is flagged if EITHER layer flags it --
this is a logical OR, not a vote or an average, because the two layers
catch different, largely non-overlapping attack types (exact-phrase vs.
semantic similarity). Requiring both to agree would only let through
attacks that fool one layer, which defeats the point of having two.
"""

from pydantic import BaseModel

from firewall.sanitizer import AttackCategory, scan
from firewall.vector_filter import VectorFilterResult, check


class PipelineResult(BaseModel):
    flagged: bool
    sanitizer_flagged: bool
    sanitizer_categories: list[AttackCategory]
    vector_flagged: bool
    vector_similarity: float
    vector_nearest_attack: str | None


def evaluate(text: str, vector_threshold: float = 0.55) -> PipelineResult:
    sanitizer_result = scan(text)
    vector_result: VectorFilterResult = check(text, threshold=vector_threshold)

    return PipelineResult(
        flagged=sanitizer_result.flagged or vector_result.flagged,
        sanitizer_flagged=sanitizer_result.flagged,
        sanitizer_categories=sanitizer_result.matched_categories,
        vector_flagged=vector_result.flagged,
        vector_similarity=vector_result.max_similarity,
        vector_nearest_attack=vector_result.nearest_attack_text,
    )
