"""
OpenAI / Azure OpenAI client wrapper.

Provides a thin async client used by the LLM Judge and any future
LLM-dependent services.  Keeps all OpenAI configuration in one place.
"""

from functools import lru_cache

from app.core.config import settings
from app.core.llm_judge import LLMJudge


@lru_cache(maxsize=1)
def get_llm_judge() -> LLMJudge:
    """Return a module-level singleton LLM Judge."""
    if not settings.OPENAI_API_KEY:
        import logging
        logging.getLogger(__name__).warning(
            "OPENAI_API_KEY is not set — LLM Judge will always trigger the fail-safe."
        )
    return LLMJudge()
