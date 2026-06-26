"""FastAPI application — streaming /chat endpoint.

Request lifecycle (BUILD_SPEC section 8): authenticate -> resolve permissions (refuse on
failure) -> orchestrate -> stream. Every request produces an audit row (in the orchestrator).
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.auth.oidc import AuthError, verify_token
from app.auth.permissions import (
    PermissionError_,
    resolve_permissions,
    user_from_claims,
)
from app.data.db import close_pools, init_pools
from app.masking.vault_redis import RedisTokenVault
from app.models import Permissions, User
from app.observability import get_logger
from app.orchestrator.graph import run_chat_stream

log = get_logger(__name__)
_vault = RedisTokenVault()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await init_pools()
    try:
        yield
    finally:
        await close_pools()


app = FastAPI(title="Governed RAG Chatbot", lifespan=lifespan)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)


# --- Auth dependency: returns (User, Permissions) or refuses --------------------------------


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token"
        )
    return authorization.split(" ", 1)[1].strip()


async def authorize(
    authorization: str | None = Header(default=None),
) -> tuple[User, Permissions]:
    token = _bearer(authorization)
    try:
        claims = verify_token(token)
        user = user_from_claims(claims)
    except (AuthError, PermissionError_):
        # Generic message; never echo token material (invariant #7).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed"
        )
    try:
        permissions = resolve_permissions(user)
    except PermissionError_ as exc:
        # Authenticated but no usable authorization -> refuse (BUILD_SPEC section 8).
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"not authorized: {exc}"
        )
    return user, permissions


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat")
async def chat(
    req: ChatRequest,
    principal: tuple[User, Permissions] = Depends(authorize),
) -> StreamingResponse:
    user, permissions = principal
    request_id = uuid.uuid4().hex

    async def event_stream() -> AsyncIterator[bytes]:
        async for event in run_chat_stream(
            request_id=request_id,
            message=req.message,
            user=user,
            permissions=permissions,
            vault=_vault,
        ):
            yield f"data: {json.dumps(event)}\n\n".encode()
        yield b"data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
