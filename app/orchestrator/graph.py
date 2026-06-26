"""Orchestrator (Phases 1-2).

Implements the flow from BUILD_SPEC section 6 for the structured path:

    guardrails_in -> resolve_permissions(*) -> route -> sql_tool -> mask
                  -> synthesize -> reidentify -> guardrails_out -> audit

(* permissions are resolved before this is called, by the API auth dependency, so a
failure refuses the request before any work — BUILD_SPEC section 8.)

Phase 4 will replace this hand-wired pipeline with a compiled LangGraph graph and add the
retrieval branch. The node functions it calls are already the final ones, so that swap is
mechanical. Streaming note: reidentification (invariant #6) needs the COMPLETE answer text,
so we synthesize fully, reidentify, run the output guard, then stream the final answer to
the client. The transport stays a streaming response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from app.masking.interface import TokenVault
from app.models import Citation, Context, Path, Permissions
from app.nodes import guardrails_in, guardrails_out, reidentify, route
from app.nodes.audit import write_audit
from app.nodes.mask import mask_structured
from app.nodes.synthesize import synthesize_answer
from app.nodes.sql_tool import run_sql_path
from app.observability import get_logger, redact
from app.models import User

log = get_logger(__name__)


@dataclass
class ChatResult:
    answer: str | None
    citations: list[Citation] = field(default_factory=list)
    refused: bool = False
    reason: str | None = None


async def run_chat(
    *,
    request_id: str,
    message: str,
    user: User,
    permissions: Permissions,
    vault: TokenVault,
) -> ChatResult:
    """Run the full Phase 1-2 pipeline and return a complete (reidentified) result."""
    # 1. Input guardrail.
    decision = guardrails_in.check_input(message, user)
    if not decision.allow:
        await write_audit(
            user_id=permissions.user_id,
            masked_question=redact(message),
            sources=None,
            decision=f"refused:{decision.reason}",
        )
        return ChatResult(answer=None, refused=True, reason=decision.reason)

    # 2. Route.
    path = route.route(message, permissions)
    if path is not Path.SQL:
        # Retrieval path arrives in Phase 3.
        await write_audit(
            user_id=permissions.user_id,
            masked_question=redact(message),
            sources=None,
            decision="refused:unsupported_path",
        )
        return ChatResult(answer=None, refused=True, reason="path not available yet")

    # 3. Structured retrieval (read-only masked role + RLS).
    result: dict[str, Any] = await run_sql_path(message, permissions)

    # 4. Mask (left slice of the sandwich) + stash token map in the vault.
    masked_result, forbidden = mask_structured(
        request_id=request_id,
        result=result,
        permissions=permissions,
        vault=vault,
    )

    # 5. Synthesize over masked content only (Groq; guard aborts on any raw leak).
    raw_answer = synthesize_answer(message, masked_result, forbidden_values=forbidden)

    # 6. Reidentify per permission (invariant #6).
    answer = reidentify.reidentify(
        request_id=request_id,
        text=raw_answer,
        permissions=permissions,
        vault=vault,
    )

    citations = [Citation(kind=s["kind"], ref=s["ref"]) for s in result["sources"]]
    context = Context(path=Path.SQL, masked_text=str(masked_result["rows"]), citations=citations,
                      sources=result["sources"])

    # 7. Output guardrail.
    out = guardrails_out.check_output(answer, context, user)
    if not out.allow:
        await write_audit(
            user_id=permissions.user_id,
            masked_question=redact(message),
            sources=result["sources"],
            decision=f"refused:{out.reason}",
        )
        return ChatResult(answer=None, refused=True, reason=out.reason)

    # 8. Audit (answered). Question stored redacted; Phase 3 routes it through Presidio first.
    await write_audit(
        user_id=permissions.user_id,
        masked_question=redact(message),
        sources=result["sources"],
        decision="answered",
    )

    return ChatResult(answer=answer, citations=citations)


async def run_chat_stream(
    *,
    request_id: str,
    message: str,
    user: User,
    permissions: Permissions,
    vault: TokenVault,
) -> AsyncIterator[dict[str, Any]]:
    """Yield SSE-style events for the API. Streams the final (reidentified) answer."""
    result = await run_chat(
        request_id=request_id,
        message=message,
        user=user,
        permissions=permissions,
        vault=vault,
    )
    if result.refused:
        yield {"type": "refusal", "reason": result.reason or "request refused"}
        return

    answer = result.answer or ""
    # Chunk the final answer for a streaming UX.
    chunk = 64
    for i in range(0, len(answer), chunk):
        yield {"type": "token", "text": answer[i : i + chunk]}
    yield {
        "type": "citations",
        "citations": [{"kind": c.kind, "ref": c.ref} for c in result.citations],
    }
