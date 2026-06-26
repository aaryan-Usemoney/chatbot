"""Lightweight in-process metrics (Phase 5).

A dependency-free counter + summary registry rendered in Prometheus text format at /metrics.
No PII or secrets are ever used as label values (invariant #7) — labels are bounded
enumerations (path, outcome, reason). Swap for a real Prometheus client later if needed.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
# name -> (sum, count) for simple latency summaries
_summaries: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])


def _label_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def inc(name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
    with _lock:
        _counters[(name, _label_key(labels))] += value


def observe(name: str, value: float) -> None:
    with _lock:
        s = _summaries[name]
        s[0] += value
        s[1] += 1.0


def reset() -> None:
    """Test helper: clear all metrics."""
    with _lock:
        _counters.clear()
        _summaries.clear()


def snapshot() -> dict[str, float]:
    """Flat dict view for assertions/tests."""
    with _lock:
        out: dict[str, float] = {}
        for (name, labels), v in _counters.items():
            label_str = ",".join(f"{k}={val}" for k, val in labels)
            out[f"{name}{{{label_str}}}"] = v
        for name, (total, count) in _summaries.items():
            out[f"{name}_sum"] = total
            out[f"{name}_count"] = count
        return out


def render() -> str:
    """Render Prometheus text exposition format."""
    lines: list[str] = []
    with _lock:
        for (name, labels), v in sorted(_counters.items()):
            if labels:
                label_str = ",".join(f'{k}="{val}"' for k, val in labels)
                lines.append(f"{name}{{{label_str}}} {v}")
            else:
                lines.append(f"{name} {v}")
        for name, (total, count) in sorted(_summaries.items()):
            lines.append(f"{name}_sum {total}")
            lines.append(f"{name}_count {count}")
    return "\n".join(lines) + "\n"
