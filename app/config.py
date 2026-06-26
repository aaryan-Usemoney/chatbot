"""Env-driven settings. Secrets are read from the environment only (invariant #7).

Nothing in this module is ever logged. ``repr`` of secret-bearing fields is suppressed
by pydantic's ``SecretStr``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- LLM (Groq) ---
    groq_api_key: SecretStr = Field(default=SecretStr(""), alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")
    groq_base_url: str = Field(
        default="https://api.groq.com/openai/v1", alias="GROQ_BASE_URL"
    )
    groq_zdr_confirmed: bool = Field(default=False, alias="GROQ_ZDR_CONFIRMED")

    # --- Embeddings (local) ---
    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5", alias="EMBEDDING_MODEL")

    # --- PII detection (local, Presidio) ---
    presidio_spacy_model: str = Field(default="en_core_web_lg", alias="PRESIDIO_SPACY_MODEL")

    # --- Postgres ---
    database_url: SecretStr = Field(default=SecretStr(""), alias="DATABASE_URL")
    database_url_readonly: SecretStr = Field(
        default=SecretStr(""), alias="DATABASE_URL_READONLY"
    )

    # --- Infra ---
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # --- Auth ---
    oidc_issuer: str = Field(default="", alias="OIDC_ISSUER")
    oidc_audience: str = Field(default="", alias="OIDC_AUDIENCE")
    oidc_jwks_url: str = Field(default="", alias="OIDC_JWKS_URL")
    auth_dev_mode: bool = Field(default=False, alias="AUTH_DEV_MODE")
    auth_dev_hs256_secret: SecretStr = Field(
        default=SecretStr(""), alias="AUTH_DEV_HS256_SECRET"
    )

    # --- Misc ---
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    app_env: str = Field(default="local", alias="APP_ENV")
    # Token vault TTL in seconds (per-request map lifetime).
    vault_ttl_seconds: int = Field(default=300, alias="VAULT_TTL_SECONDS")

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in {"prod", "production"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
