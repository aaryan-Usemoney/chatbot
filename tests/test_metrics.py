"""Phase 5: metrics registry counts and renders; no PII in labels."""

from __future__ import annotations

from app import metrics


def test_counters_summaries_and_render():
    metrics.reset()
    metrics.inc("chat_requests_total", {"path": "sql", "outcome": "answered"})
    metrics.inc("chat_requests_total", {"path": "sql", "outcome": "answered"})
    metrics.inc("chat_refusals_total", {"reason": "injection"})
    metrics.observe("chat_latency_seconds", 0.12)

    snap = metrics.snapshot()
    assert snap["chat_requests_total{outcome=answered,path=sql}"] == 2.0
    assert snap["chat_refusals_total{reason=injection}"] == 1.0
    assert snap["chat_latency_seconds_count"] == 1.0

    text = metrics.render()
    assert 'chat_requests_total{outcome="answered",path="sql"} 2.0' in text
    assert "chat_latency_seconds_sum" in text
    metrics.reset()
