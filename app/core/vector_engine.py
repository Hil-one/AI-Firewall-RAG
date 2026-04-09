"""
Tier 1 — Vector-based similarity engine.

Searches a vector store (ChromaDB or Qdrant) for known malicious signatures.
Returns the cosine similarity score against the nearest neighbour.

OWASP LLM01: Prompt Injection
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class VectorSearchResult:
    similarity_score: float
    matched_signature: str | None
    owasp_category: str = "LLM01"


class BaseVectorEngine(ABC):
    """Abstract interface — swap backends without touching detection logic."""

    @abstractmethod
    async def search(self, text: str, top_k: int = 1) -> VectorSearchResult:
        """Return the highest-similarity match from the malicious signature store."""
        ...

    @abstractmethod
    async def add_signature(self, text: str, metadata: dict | None = None) -> None:
        """Insert a new malicious signature into the store."""
        ...


class ChromaVectorEngine(BaseVectorEngine):
    """ChromaDB-backed vector engine."""

    def __init__(self) -> None:
        import chromadb  # type: ignore[import]

        self._client = chromadb.HttpClient(
            host=settings.CHROMA_HOST,
            port=settings.CHROMA_PORT,
        )
        self._collection = self._client.get_or_create_collection(
            name=settings.VECTOR_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "ChromaVectorEngine initialised (host=%s, port=%d, collection=%s)",
            settings.CHROMA_HOST,
            settings.CHROMA_PORT,
            settings.VECTOR_COLLECTION_NAME,
        )

    async def search(self, text: str, top_k: int = 1) -> VectorSearchResult:
        results = self._collection.query(
            query_texts=[text],
            n_results=top_k,
            include=["documents", "distances"],
        )
        if not results["distances"] or not results["distances"][0]:
            return VectorSearchResult(similarity_score=0.0, matched_signature=None)

        # ChromaDB cosine distance: 0 = identical, 1 = orthogonal.
        distance = results["distances"][0][0]
        similarity = 1.0 - distance
        matched = (results["documents"][0][0] if results["documents"] else None)

        logger.info(
            "Vector search | similarity=%.4f | owasp=LLM01",
            similarity,
        )
        return VectorSearchResult(similarity_score=similarity, matched_signature=matched)

    async def add_signature(self, text: str, metadata: dict | None = None) -> None:
        import uuid
        self._collection.add(
            documents=[text],
            metadatas=[metadata or {}],
            ids=[str(uuid.uuid4())],
        )


class QdrantVectorEngine(BaseVectorEngine):
    """Qdrant-backed vector engine."""

    def __init__(self) -> None:
        from qdrant_client import AsyncQdrantClient  # type: ignore[import]
        from qdrant_client.models import Distance, VectorParams  # type: ignore[import]

        self._client = AsyncQdrantClient(url=settings.QDRANT_URL)
        self._collection = settings.VECTOR_COLLECTION_NAME
        logger.info(
            "QdrantVectorEngine initialised (url=%s, collection=%s)",
            settings.QDRANT_URL,
            self._collection,
        )

    async def search(self, text: str, top_k: int = 1) -> VectorSearchResult:
        raise NotImplementedError("Qdrant search requires an embedding model — wire up in services/vector_db.py")

    async def add_signature(self, text: str, metadata: dict | None = None) -> None:
        raise NotImplementedError("Qdrant upsert requires an embedding model — wire up in services/vector_db.py")


def get_vector_engine() -> BaseVectorEngine:
    """Factory: returns the configured vector engine backend."""
    backend = settings.VECTOR_DB_BACKEND.lower()
    if backend == "chroma":
        return ChromaVectorEngine()
    if backend == "qdrant":
        return QdrantVectorEngine()
    raise ValueError(f"Unsupported VECTOR_DB_BACKEND: {backend!r}")
