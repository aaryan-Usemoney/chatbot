"""Phase 3: retrieval uses the local embedder (invariant #4) and is fail-closed (invariant #2)."""

from __future__ import annotations

import pytest

import app.nodes.retrieval_tool as rt
from app.data import embeddings
from app.data.db import run_readonly_vector_search
from app.data.embeddings import EMBEDDING_DIM
from app.models import Permissions


class _FakeEncoder:
    """Local, offline encoder — proves no external embedding call is needed (invariant #4)."""

    def __init__(self) -> None:
        self.calls = 0

    def encode(self, texts: list[str]) -> list[list[float]]:
        self.calls += 1
        return [[0.1] * EMBEDDING_DIM for _ in texts]


@pytest.fixture
def fake_encoder():
    enc = _FakeEncoder()
    embeddings.set_encoder(enc)
    yield enc
    embeddings.set_encoder(None)


async def test_retrieval_embeds_locally_and_returns_citations(fake_encoder, monkeypatch, manager_perms):
    captured: dict = {}

    async def fake_search(qvec, perms, *, k):
        captured["perms"] = perms
        captured["qvec"] = qvec
        return [
            {"id": 1, "document_id": "doc1", "content": "alpha", "metadata": {}, "similarity": 0.9},
            {"id": 2, "document_id": "doc1", "content": "beta", "metadata": {}, "similarity": 0.8},
            {"id": 3, "document_id": "doc2", "content": "gamma", "metadata": {}, "similarity": 0.7},
        ]

    monkeypatch.setattr(rt, "run_readonly_vector_search", fake_search)

    out = await rt.run_retrieval_path("according to the policy?", manager_perms)

    assert fake_encoder.calls == 1  # local embedder was used
    assert len(captured["qvec"]) == EMBEDDING_DIM
    assert captured["perms"] is manager_perms  # permissions drive the filter
    # distinct documents become citations, in first-seen order
    assert out["sources"] == [
        {"kind": "document", "ref": "doc1"},
        {"kind": "document", "ref": "doc2"},
    ]
    assert len(out["chunks"]) == 3


async def test_vector_search_fail_closed_without_tags():
    perms = Permissions(
        user_id="x", roles=frozenset(), allowed_tags=frozenset(), row_scopes={}
    )
    # No allowed tags -> no query is issued and nothing is returned (fail-closed).
    assert await run_readonly_vector_search([0.0] * EMBEDDING_DIM, perms) == []


@pytest.mark.integration
async def test_doc_chunks_rls_isolates_by_tags():
    """Ingest two docs with disjoint tags; each scope retrieves only its own (RLS + filter)."""
    from app.data.db import close_pools, init_pools
    from app.data.ingest import ingest_document

    await init_pools()
    try:
        await ingest_document(
            document_id="sales-doc", text="The sales playbook covers EMEA pricing.",
            access_tags=["sales"],
        )
        await ingest_document(
            document_id="hr-doc", text="The HR handbook covers leave policy.",
            access_tags=["hr"],
        )

        sales_only = Permissions(
            user_id="a", roles=frozenset({"analyst"}), allowed_tags=frozenset({"sales"}),
            row_scopes={},
        )
        hr_only = Permissions(
            user_id="b", roles=frozenset({"hruser"}), allowed_tags=frozenset({"hr"}),
            row_scopes={},
        )

        q = embeddings.embed_query("what does the policy say")
        sales_docs = {c["document_id"] for c in await run_readonly_vector_search(q, sales_only, k=10)}
        hr_docs = {c["document_id"] for c in await run_readonly_vector_search(q, hr_only, k=10)}

        assert "sales-doc" in sales_docs and "hr-doc" not in sales_docs
        assert "hr-doc" in hr_docs and "sales-doc" not in hr_docs
    finally:
        await close_pools()
