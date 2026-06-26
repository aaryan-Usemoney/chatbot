"""Self-hosted embeddings (invariant #4).

Document and query text is embedded by a local sentence-transformers model. Text is NEVER
sent to an external embedding API — this module makes no network calls. The model is loaded
lazily (so importing the package does not pull in torch) and cached process-wide.

``EMBEDDING_DIM`` must match the ``vector(N)`` column in db/002_schema.sql.
"""

from __future__ import annotations

from typing import Protocol

from app.config import get_settings

EMBEDDING_DIM = 384  # BAAI/bge-small-en-v1.5; keep in sync with doc_chunks.embedding


class Encoder(Protocol):
    def encode(self, texts: list[str]) -> list[list[float]]: ...


_model: Encoder | None = None


def set_encoder(encoder: Encoder | None) -> None:
    """Inject an encoder (used by tests to avoid loading torch). Pass None to reset."""
    global _model
    _model = encoder


def _get_model() -> Encoder:
    global _model
    if _model is None:
        # Lazy import: heavy deps only loaded when embeddings are actually needed.
        from sentence_transformers import SentenceTransformer

        st = SentenceTransformer(get_settings().embedding_model)

        class _STEncoder:
            def encode(self, texts: list[str]) -> list[list[float]]:
                # normalize so cosine distance is well-behaved with pgvector.
                vecs = st.encode(texts, normalize_embeddings=True)
                return [list(map(float, v)) for v in vecs]

        _model = _STEncoder()
    return _model


def embed_texts(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    return _get_model().encode(texts)


def embed_query(text: str) -> list[float]:
    return embed_texts([text])[0]
