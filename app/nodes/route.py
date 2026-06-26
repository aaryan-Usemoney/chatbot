"""Router — picks the structured (SQL) or unstructured (retrieval) path.

Phase 2: the retrieval path is not built yet, so we route everything to SQL. Phase 4 will
replace this with an LLM/heuristic router over the masked question. Kept as a seam so the
orchestrator wiring is final.
"""

from __future__ import annotations

from app.models import Path, Permissions


def route(question: str, permissions: Permissions) -> Path:  # noqa: ARG001
    # TODO(Phase 3/4): choose RETRIEVAL for document-shaped questions once ingest lands.
    return Path.SQL
