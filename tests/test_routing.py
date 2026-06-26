"""Phase 3: router sends document questions to retrieval, analytics to SQL."""

from __future__ import annotations

import pytest

from app.models import Path
from app.nodes.route import route


@pytest.mark.parametrize(
    "question",
    [
        "What does the security policy say about access?",
        "According to the handbook, what is the leave process?",
        "Summarize section 3 of the contract",
    ],
)
def test_document_questions_route_to_retrieval(question, manager_perms):
    assert route(question, manager_perms) is Path.RETRIEVAL


@pytest.mark.parametrize(
    "question",
    [
        "How many sales did we close in EMEA?",
        "What is the total revenue by region?",
        "Average amount per product last month",
    ],
)
def test_analytics_questions_route_to_sql(question, manager_perms):
    assert route(question, manager_perms) is Path.SQL


def test_ambiguous_defaults_to_sql(manager_perms):
    assert route("Tell me about Alice", manager_perms) is Path.SQL
