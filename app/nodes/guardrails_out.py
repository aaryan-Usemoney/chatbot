"""Output guardrails (BUILD_SPEC section 6).

Phase 2 ships a minimal output guard. The substantive groundedness check (block answers
not supported by retrieved context) and PII-leak scan land in Phase 4. Wired now so the
orchestrator can call it unconditionally and fail closed.
"""

from __future__ import annotations

from app.models import Context, Decision, User


def check_output(answer: str, context: Context, user: User) -> Decision:  # noqa: ARG001
    if not answer or not answer.strip():
        return Decision(allow=False, reason="empty answer")
    # TODO(Phase 4): groundedness check against context.masked_text; PII-leak scan.
    return Decision(allow=True)
