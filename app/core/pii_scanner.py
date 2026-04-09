"""
Tier 3 — PII / Sensitive Information Scanner.

Uses Microsoft Presidio to detect and redact PII in LLM outputs before
final delivery to the caller.

OWASP LLM06: Sensitive Information Disclosure
"""

import logging

from presidio_analyzer import AnalyzerEngine  # type: ignore[import]
from presidio_anonymizer import AnonymizerEngine  # type: ignore[import]
from presidio_anonymizer.entities import OperatorConfig  # type: ignore[import]

from app.core.config import settings
from app.models.schemas import AuditResponse, PIIEntity

logger = logging.getLogger(__name__)


class PIIScanner:
    """
    Wraps Presidio Analyzer + Anonymizer for PII detection and redaction.

    Detected entities are replaced with <ENTITY_TYPE> placeholders in the
    redacted output so downstream consumers receive safe text.
    """

    def __init__(self) -> None:
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()
        self._languages = settings.PRESIDIO_SUPPORTED_LANGUAGES
        self._score_threshold = settings.PII_SCORE_THRESHOLD
        logger.info(
            "PIIScanner initialised (languages=%s, threshold=%.2f)",
            self._languages,
            self._score_threshold,
        )

    async def scan(self, text: str, request_id: str | None = None) -> AuditResponse:
        """
        Analyse `text` for PII and return a structured AuditResponse.
        Redaction replaces each entity with <ENTITY_TYPE>.
        """
        analyzer_results = self._analyzer.analyze(
            text=text,
            language=self._languages[0],
            score_threshold=self._score_threshold,
        )

        if not analyzer_results:
            logger.info("PII scan: clean | owasp=LLM06 | request_id=%s", request_id)
            return AuditResponse(
                status="clean",
                pii_entities=[],
                redacted_output=text,
                request_id=request_id,
            )

        pii_entities = [
            PIIEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                text=text[r.start : r.end],
            )
            for r in analyzer_results
        ]

        operators = {
            r.entity_type: OperatorConfig("replace", {"new_value": f"<{r.entity_type}>"})
            for r in analyzer_results
        }
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )

        logger.warning(
            "PII scan: %d entities detected | owasp=LLM06 | request_id=%s",
            len(pii_entities),
            request_id,
        )

        return AuditResponse(
            status="pii_detected",
            pii_entities=pii_entities,
            redacted_output=anonymized.text,
            request_id=request_id,
        )
