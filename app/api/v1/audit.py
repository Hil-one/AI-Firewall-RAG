"""
POST /v1/audit

Scans an LLM output for PII / sensitive information before it is
delivered to the end user.

OWASP LLM06: Sensitive Information Disclosure
"""

import logging
from functools import lru_cache

from fastapi import APIRouter

from app.core.pii_scanner import PIIScanner
from app.models.schemas import AuditRequest, AuditResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_pii_scanner() -> PIIScanner:
    return PIIScanner()


@router.post("/audit", response_model=AuditResponse)
async def audit(payload: AuditRequest) -> AuditResponse:
    """
    Scan the LLM output for PII entities.

    Returns a redacted version of the output and a list of detected
    PII entities with their type, position, and confidence score.
    """
    logger.info("Audit request received | request_id=%s | owasp=LLM06", payload.request_id)

    scanner = _get_pii_scanner()
    result = await scanner.scan(text=payload.llm_output, request_id=payload.request_id)
    return result
