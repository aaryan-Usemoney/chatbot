"""FastAPI application — streaming /chat endpoint.

Request lifecycle (BUILD_SPEC section 8): authenticate -> resolve permissions (refuse on
failure) -> orchestrate -> stream. Every request produces an audit row (in the orchestrator).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from app import metrics
from app.auth.oidc import AuthError, verify_token
from app.auth.permissions import (
    PermissionError_,
    resolve_permissions,
    user_from_claims,
)
from app.config import get_settings
from app.data.db import close_pools, init_pools
from app.masking.vault_redis import RedisTokenVault
from app.models import Permissions, User
from app.observability import get_logger
from app.orchestrator.graph import run_chat_stream

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

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


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


class DevTokenRequest(BaseModel):
    sub: str = Field(default="dev-user", max_length=128)
    roles: list[str] = Field(default_factory=lambda: ["manager"])
    region: str = Field(default="EMEA", max_length=64)


@app.post("/dev/token")
async def dev_token(req: DevTokenRequest) -> dict[str, str]:
    """DEV-ONLY: mint an HS256 token so the thin UI works without a real IdP.

    Hard-gated: returns 404 unless AUTH_DEV_MODE is on and APP_ENV is non-production. This
    endpoint must never be reachable in a deployed environment.
    """
    settings = get_settings()
    if settings.is_production or not settings.auth_dev_mode:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    secret = settings.auth_dev_hs256_secret.get_secret_value()
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    now = int(time.time())
    claims = {
        "sub": req.sub,
        "roles": req.roles,
        "region": req.region,
        "iat": now,
        "exp": now + 3600,
    }
    if settings.oidc_audience:
        claims["aud"] = settings.oidc_audience
    return {"token": jwt.encode(claims, secret, algorithm="HS256")}


@app.get("/metrics")
async def metrics_endpoint() -> PlainTextResponse:
    # Prometheus text exposition. No PII/secrets in labels (invariant #7).
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


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
