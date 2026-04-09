"""
Vector DB service — dependency-injected singleton for the vector engine.

Import `get_engine` in routes/core modules to obtain the shared instance.
"""

from functools import lru_cache

from app.core.vector_engine import BaseVectorEngine, get_vector_engine


@lru_cache(maxsize=1)
def get_engine() -> BaseVectorEngine:
    """Return a module-level singleton of the configured vector engine."""
    return get_vector_engine()
