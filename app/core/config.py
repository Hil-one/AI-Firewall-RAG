"""
Application configuration — loaded from environment variables via Pydantic Settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── General ────────────────────────────────────────────────────────────────
    APP_ENV: str = "development"
    DRY_RUN: bool = False
    ALLOWED_ORIGINS: list[str] = ["*"]

    # ── Vector DB ──────────────────────────────────────────────────────────────
    VECTOR_DB_BACKEND: str = "chroma"          # "chroma" | "qdrant"
    CHROMA_HOST: str = "localhost"
    CHROMA_PORT: int = 8000
    QDRANT_URL: str = "http://localhost:6333"
    VECTOR_COLLECTION_NAME: str = "malicious_signatures"

    # ── Detection Thresholds ───────────────────────────────────────────────────
    # Tier 1: block immediately if similarity > BLOCK_THRESHOLD
    BLOCK_THRESHOLD: float = 0.80
    # Tier 2: escalate to LLM Judge if similarity is in [ESCALATE_LOW, BLOCK_THRESHOLD)
    ESCALATE_LOW: float = 0.60

    # ── LLM Judge ─────────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    LLM_JUDGE_TIMEOUT_SECONDS: int = 10
    # Fail-safe: what to do when LLM Judge is unreachable ("allow" | "block")
    LLM_JUDGE_FAILSAFE: str = "block"

    # ── PII / Presidio ─────────────────────────────────────────────────────────
    PRESIDIO_SUPPORTED_LANGUAGES: list[str] = ["en"]
    PII_SCORE_THRESHOLD: float = 0.70


settings = Settings()
