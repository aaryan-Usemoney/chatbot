"""Phase 5 acceptance: the eval harness meets its thresholds (and zero leakage)."""

from __future__ import annotations

from app.eval.harness import THRESHOLDS, run_eval


def test_eval_meets_all_thresholds():
    r = run_eval()
    assert r.leakage_count == 0
    assert r.routing_accuracy >= THRESHOLDS["routing_accuracy"]
    assert r.input_guardrail_accuracy >= THRESHOLDS["input_guardrail_accuracy"]
    assert r.output_guardrail_accuracy >= THRESHOLDS["output_guardrail_accuracy"]
    assert r.passed is True
