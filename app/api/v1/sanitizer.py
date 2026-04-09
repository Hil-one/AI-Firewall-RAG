"""
POST /v1/sanitizer

Evaluates an incoming prompt + RAG-retrieved context against the
three-tier detection pipeline:

  Tier 1 — Vector similarity against known malicious signatures (OWASP LLM01)
  Tier 2 — LLM-as-a-Judge for gray-zone scores
  DRY_RUN — Log the threat but always return status "allowed"
"""

import logging
import uuid

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.llm_judge import JudgeVerdict
from app.core.vector_engine import BaseVectorEngine
from app.models.schemas import ReasoningDetail, SanitizerRequest, SanitizerResponse
from app.services.openai_client import get_llm_judge
from app.services.vector_db import get_engine

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/sanitizer", response_model=SanitizerResponse)
async def sanitize(
    payload: SanitizerRequest,
    engine: BaseVectorEngine = Depends(get_engine),
) -> SanitizerResponse:
    """
    Analyse the prompt and retrieved context for prompt injection threats.

    Returns `status: "blocked"` (or `"allowed"` in DRY_RUN mode) with a
    detailed reasoning object and OWASP category mapping.
    """
    request_id = str(uuid.uuid4())
    dry_run = payload.dry_run or settings.DRY_RUN

    # Combine prompt + context into a single text blob for analysis.
    combined_text = payload.prompt + "\n\n" + "\n\n".join(payload.retrieved_context)

    # ── Tier 1: Vector Similarity ─────────────────────────────────────────────
    vector_result = await engine.search(combined_text)
    score = vector_result.similarity_score

    logger.info(
        "Sanitizer | request_id=%s | similarity=%.4f | dry_run=%s",
        request_id,
        score,
        dry_run,
    )

    # Immediate block: score exceeds hard threshold.
    if score >= settings.BLOCK_THRESHOLD:
        return _build_response(
            request_id=request_id,
            threat_detected=True,
            status="allowed" if dry_run else "blocked",
            score=score,
            reasoning=ReasoningDetail(
                method="vector_similarity",
                owasp_category="LLM01",
                explanation=(
                    f"High-confidence prompt injection detected via vector similarity "
                    f"(score={score:.4f} ≥ threshold={settings.BLOCK_THRESHOLD})."
                ),
            ),
            dry_run=dry_run,
        )

    # ── Tier 2: LLM Judge (gray zone) ────────────────────────────────────────
    if settings.ESCALATE_LOW <= score < settings.BLOCK_THRESHOLD:
        judge = get_llm_judge()
        judge_result = await judge.evaluate(combined_text)

        if judge_result.verdict == JudgeVerdict.MALICIOUS:
            return _build_response(
                request_id=request_id,
                threat_detected=True,
                status="allowed" if dry_run else "blocked",
                score=score,
                reasoning=ReasoningDetail(
                    method="failsafe" if judge_result.used_failsafe else "llm_judge",
                    owasp_category="LLM01",
                    explanation=judge_result.explanation,
                ),
                dry_run=dry_run,
            )

    # ── Clean ─────────────────────────────────────────────────────────────────
    return _build_response(
        request_id=request_id,
        threat_detected=False,
        status="allowed",
        score=score,
        reasoning=ReasoningDetail(
            method="vector_similarity",
            owasp_category=None,
            explanation="No prompt injection indicators detected.",
        ),
        dry_run=False,
    )


def _build_response(
    *,
    request_id: str,
    threat_detected: bool,
    status: str,
    score: float,
    reasoning: ReasoningDetail,
    dry_run: bool,
) -> SanitizerResponse:
    if dry_run and threat_detected:
        logger.warning(
            "DRY_RUN | threat suppressed | request_id=%s | owasp=%s",
            request_id,
            reasoning.owasp_category,
        )
        reasoning = ReasoningDetail(
            method="dry_run",
            owasp_category=reasoning.owasp_category,
            explanation=f"[DRY RUN] {reasoning.explanation}",
        )

    return SanitizerResponse(
        status=status,  # type: ignore[arg-type]
        threat_detected=threat_detected,
        similarity_score=score,
        reasoning=reasoning,
        request_id=request_id,
    )
