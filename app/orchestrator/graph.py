"""Orchestrator — the compiled LangGraph graph (Phase 4).

Wires the nodes from BUILD_SPEC section 6:

    guardrails_in -> resolve_permissions -> route -> {sql_tool | retrieval_tool}
                  -> mask -> synthesize -> reidentify -> guardrails_out -> audit

A failed guardrail (in or out) routes to a safe-refusal node; both refusal and answer paths
terminate at the audit node, so EVERY request produces exactly one audit row. The masking
sandwich (mask -> synthesize -> reidentify) lives entirely inside the graph.

Note on resolve_permissions: permissions are resolved in the API auth dependency BEFORE the
graph runs, so a resolution failure refuses the request before any work (BUILD_SPEC section 8).
The ``resolve_permissions`` graph node here is a presence/validation checkpoint that keeps the
wiring faithful to the spec diagram and fails closed if permissions are somehow absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from app.models import Citation, Context, Path, Permissions, User
from app.nodes import guardrails_in, guardrails_out, reidentify, route
from app.nodes.audit import write_audit
from app.nodes.mask import mask_structured, mask_unstructured
from app.nodes.retrieval_tool import run_retrieval_path
from app.nodes.sql_tool import run_sql_path
from app.nodes.synthesize import synthesize_answer, synthesize_answer_from_chunks
from app.observability import get_logger, redact

log = get_logger(__name__)

_NO_DOCS_MSG = (
    "I don't have any documents you're permitted to see that match that question."
)


@dataclass
class ChatResult:
    answer: str | None
    citations: list[Citation] = field(default_factory=list)
    refused: bool = False
    reason: str | None = None


class ChatState(TypedDict, total=False):
    # inputs
    request_id: str
    message: str
    user: User
    permissions: Permissions
    vault: Any
    # working state
    path: str
    result: dict[str, Any]
    masked_result: dict[str, Any]
    masked_text: str
    forbidden: list[str]
    raw_answer: str
    sources: list[dict[str, Any]]
    citations: list[Citation]
    # outputs
    answer: Optional[str]
    refused: bool
    reason: Optional[str]
    decision: str


# --- nodes ------------------------------------------------------------------------------


async def n_guardrails_in(state: ChatState) -> dict[str, Any]:
    d = guardrails_in.check_input(state["message"], state["user"])
    if not d.allow:
        return {"refused": True, "reason": d.reason, "decision": f"refused:{d.reason}"}
    return {}


async def n_resolve_permissions(state: ChatState) -> dict[str, Any]:
    # Permissions are resolved pre-graph (auth dependency). Fail closed if absent.
    if state.get("permissions") is None:
        return {
            "refused": True,
            "reason": "permissions unresolved",
            "decision": "refused:permissions_unresolved",
        }
    return {}


async def n_route(state: ChatState) -> dict[str, Any]:
    return {"path": route.route(state["message"], state["permissions"]).value}


async def n_sql(state: ChatState) -> dict[str, Any]:
    result = await run_sql_path(state["message"], state["permissions"])
    return {"result": result, "sources": result["sources"]}


async def n_retrieve(state: ChatState) -> dict[str, Any]:
    result = await run_retrieval_path(state["message"], state["permissions"])
    return {"result": result, "sources": result["sources"]}


async def n_no_docs(state: ChatState) -> dict[str, Any]:
    return {
        "answer": _NO_DOCS_MSG,
        "citations": [],
        "sources": [],
        "decision": "answered:no_documents",
    }


async def n_mask(state: ChatState) -> dict[str, Any]:
    rid, perms, vault = state["request_id"], state["permissions"], state["vault"]
    if state["path"] == Path.SQL.value:
        masked, forbidden = mask_structured(
            request_id=rid, result=state["result"], permissions=perms, vault=vault
        )
        masked_text = str(masked["rows"])
    else:
        masked, forbidden = mask_unstructured(
            request_id=rid, result=state["result"], permissions=perms, vault=vault
        )
        masked_text = str([c["content"] for c in masked["chunks"]])
    citations = [Citation(kind=s["kind"], ref=s["ref"]) for s in state["sources"]]
    return {
        "masked_result": masked,
        "forbidden": forbidden,
        "masked_text": masked_text,
        "citations": citations,
    }


async def n_synthesize(state: ChatState) -> dict[str, Any]:
    if state["path"] == Path.SQL.value:
        raw = synthesize_answer(
            state["message"], state["masked_result"], forbidden_values=state["forbidden"]
        )
    else:
        raw = synthesize_answer_from_chunks(
            state["message"], state["masked_result"], forbidden_values=state["forbidden"]
        )
    return {"raw_answer": raw}


async def n_reidentify(state: ChatState) -> dict[str, Any]:
    answer = reidentify.reidentify(
        request_id=state["request_id"],
        text=state["raw_answer"],
        permissions=state["permissions"],
        vault=state["vault"],
    )
    return {"answer": answer}


async def n_guardrails_out(state: ChatState) -> dict[str, Any]:
    perms: Permissions = state["permissions"]
    token_map = state["vault"].get(state["request_id"])
    unpermitted = [
        e["value"] for e in token_map.values() if not perms.may_unmask(e["field"])
    ]
    ctx = Context(
        path=Path(state["path"]),
        masked_text=state.get("masked_text", ""),
        citations=state.get("citations", []),
        sources=state.get("sources", []),
        question=state["message"],
        unpermitted_values=unpermitted,
    )
    d = guardrails_out.check_output(state["answer"] or "", ctx, state["user"])
    if not d.allow:
        return {
            "refused": True,
            "reason": d.reason,
            "answer": None,
            "decision": f"refused:{d.reason}",
        }
    return {"decision": "answered"}


async def n_refuse(state: ChatState) -> dict[str, Any]:
    reason = state.get("reason") or "refused"
    return {
        "refused": True,
        "answer": None,
        "decision": state.get("decision") or f"refused:{reason}",
    }


async def n_audit(state: ChatState) -> dict[str, Any]:
    await write_audit(
        user_id=state["permissions"].user_id,
        masked_question=redact(state["message"]),
        sources=state.get("sources"),
        decision=state.get("decision")
        or ("refused" if state.get("refused") else "answered"),
    )
    return {}


# --- conditional edges ------------------------------------------------------------------


def _gate_in(state: ChatState) -> str:
    return "refuse" if state.get("refused") else "permissions"


def _gate_perms(state: ChatState) -> str:
    return "refuse" if state.get("refused") else "route"


def _gate_route(state: ChatState) -> str:
    p = state.get("path")
    if p == Path.SQL.value:
        return "sql"
    if p == Path.RETRIEVAL.value:
        return "retrieve"
    return "refuse"


def _gate_retrieve(state: ChatState) -> str:
    return "mask" if state["result"]["chunks"] else "no_docs"


def _gate_out(state: ChatState) -> str:
    return "refuse" if state.get("refused") else "audit"


def _build_graph():
    g = StateGraph(ChatState)
    g.add_node("guardrails_in", n_guardrails_in)
    g.add_node("permissions", n_resolve_permissions)
    g.add_node("route", n_route)
    g.add_node("sql", n_sql)
    g.add_node("retrieve", n_retrieve)
    g.add_node("no_docs", n_no_docs)
    g.add_node("mask", n_mask)
    g.add_node("synthesize", n_synthesize)
    g.add_node("reidentify", n_reidentify)
    g.add_node("guardrails_out", n_guardrails_out)
    g.add_node("refuse", n_refuse)
    g.add_node("audit", n_audit)

    g.add_edge(START, "guardrails_in")
    g.add_conditional_edges(
        "guardrails_in", _gate_in, {"refuse": "refuse", "permissions": "permissions"}
    )
    g.add_conditional_edges(
        "permissions", _gate_perms, {"refuse": "refuse", "route": "route"}
    )
    g.add_conditional_edges(
        "route", _gate_route, {"sql": "sql", "retrieve": "retrieve", "refuse": "refuse"}
    )
    g.add_edge("sql", "mask")
    g.add_conditional_edges(
        "retrieve", _gate_retrieve, {"mask": "mask", "no_docs": "no_docs"}
    )
    g.add_edge("no_docs", "audit")
    g.add_edge("mask", "synthesize")
    g.add_edge("synthesize", "reidentify")
    g.add_edge("reidentify", "guardrails_out")
    g.add_conditional_edges(
        "guardrails_out", _gate_out, {"refuse": "refuse", "audit": "audit"}
    )
    g.add_edge("refuse", "audit")
    g.add_edge("audit", END)
    return g.compile()


_graph = _build_graph()


# --- public API -------------------------------------------------------------------------


async def run_chat(
    *,
    request_id: str,
    message: str,
    user: User,
    permissions: Permissions,
    vault: Any,
) -> ChatResult:
    """Run the compiled graph end to end and return a complete (reidentified) result."""
    initial: ChatState = {
        "request_id": request_id,
        "message": message,
        "user": user,
        "permissions": permissions,
        "vault": vault,
    }
    final: ChatState = await _graph.ainvoke(initial)
    if final.get("refused"):
        return ChatResult(answer=None, refused=True, reason=final.get("reason"))
    return ChatResult(answer=final.get("answer"), citations=final.get("citations", []))


async def run_chat_stream(
    *,
    request_id: str,
    message: str,
    user: User,
    permissions: Permissions,
    vault: Any,
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
    chunk = 64
    for i in range(0, len(answer), chunk):
        yield {"type": "token", "text": answer[i : i + chunk]}
    yield {
        "type": "citations",
        "citations": [{"kind": c.kind, "ref": c.ref} for c in result.citations],
    }
