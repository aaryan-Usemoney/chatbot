"""Redis-backed TokenVault (per-request, TTL).

Stores the token -> {value, field} map for the lifetime of a request only. The map never
leaves the boundary and never enters a prompt. Swap for HashiCorp Vault later behind the
same ``TokenVault`` protocol (BUILD_SPEC section 2).
"""

from __future__ import annotations

import json

import redis

from app.config import get_settings


class RedisTokenVault:
    def __init__(self, url: str | None = None, ttl_seconds: int | None = None) -> None:
        settings = get_settings()
        self._r = redis.Redis.from_url(url or settings.redis_url, decode_responses=True)
        self._ttl = ttl_seconds or settings.vault_ttl_seconds

    @staticmethod
    def _key(request_id: str) -> str:
        return f"tokenmap:{request_id}"

    def put(self, request_id: str, token_map: dict) -> None:
        self._r.set(self._key(request_id), json.dumps(token_map), ex=self._ttl)

    def get(self, request_id: str) -> dict:
        raw = self._r.get(self._key(request_id))
        return json.loads(raw) if raw else {}

    def delete(self, request_id: str) -> None:
        self._r.delete(self._key(request_id))


class InMemoryTokenVault:
    """Process-local vault for tests and single-process dev (no Redis dependency)."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def put(self, request_id: str, token_map: dict) -> None:
        self._store[request_id] = token_map

    def get(self, request_id: str) -> dict:
        return self._store.get(request_id, {})

    def delete(self, request_id: str) -> None:
        self._store.pop(request_id, None)
