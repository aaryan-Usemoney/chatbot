"""Router — picks the structured (SQL) or unstructured (retrieval) path.

Phase 3 ships a deterministic keyword heuristic: questions that look document-oriented go to
retrieval, everything else to SQL. This keeps both paths reachable and testable. Phase 4
replaces it with an LLM/classifier router over the masked question (and may fan out to both).
"""

from __future__ import annotations

import re

from app.models import Path, Permissions

# Markers that suggest the answer lives in documents rather than structured tables.
_DOC_MARKERS = re.compile(
    r"\b(document|documents|policy|policies|report|reports|memo|contract|clause|"
    r"according to|states that|guideline|handbook|article|section|pdf)\b",
    re.IGNORECASE,
)

# Markers that strongly suggest structured analytics.
_SQL_MARKERS = re.compile(
    r"\b(how many|count|total|sum|average|avg|per |by region|by month|trend|top \d+|"
    r"revenue|sales|amount)\b",
    re.IGNORECASE,
)


def route(question: str, permissions: Permissions) -> Path:  # noqa: ARG001
    q = question or ""
    if _SQL_MARKERS.search(q):
        return Path.SQL
    if _DOC_MARKERS.search(q):
        return Path.RETRIEVAL
    # Default to the structured path (Phase 2 behavior) when ambiguous.
    return Path.SQL
