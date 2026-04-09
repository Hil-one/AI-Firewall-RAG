"""
AI Firewall - Application Entry Point
FastAPI application for protecting RAG systems against prompt injection
and sensitive information disclosure.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import sanitizer, audit
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown logic."""
    logger.info("AI Firewall starting up...")
    logger.info("DRY_RUN mode: %s", settings.DRY_RUN)
    yield
    logger.info("AI Firewall shutting down...")


app = FastAPI(
    title="AI Firewall",
    description=(
        "High-performance security microservice protecting RAG systems "
        "against Indirect Prompt Injection (OWASP LLM01) and "
        "Sensitive Information Disclosure (OWASP LLM06)."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sanitizer.router, prefix="/v1", tags=["Sanitizer"])
app.include_router(audit.router, prefix="/v1", tags=["Audit"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. The firewall encountered an unexpected condition."},
    )


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "ai-firewall"}
