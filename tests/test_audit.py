"""
Unit tests for POST /v1/audit

Covers:
- Clean output → status "clean", no entities
- Output with PII → status "pii_detected", entities returned, redacted output
- OWASP category always LLM06
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock

from app.main import app
from app.models.schemas import AuditResponse, PIIEntity


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


CLEAN_PAYLOAD = {
    "llm_output": "The quarterly earnings grew by 12% compared to last year.",
    "request_id": "test-001",
}

PII_PAYLOAD = {
    "llm_output": "Contact John Doe at john.doe@example.com or call +1-555-0199.",
    "request_id": "test-002",
}


def _mock_scanner_clean():
    scanner = MagicMock()
    scanner.scan = AsyncMock(
        return_value=AuditResponse(
            status="clean",
            pii_entities=[],
            redacted_output=CLEAN_PAYLOAD["llm_output"],
            request_id="test-001",
        )
    )
    return scanner


def _mock_scanner_pii():
    scanner = MagicMock()
    scanner.scan = AsyncMock(
        return_value=AuditResponse(
            status="pii_detected",
            pii_entities=[
                PIIEntity(entity_type="PERSON", start=8, end=16, score=0.95, text="John Doe"),
                PIIEntity(entity_type="EMAIL_ADDRESS", start=20, end=42, score=0.99, text="john.doe@example.com"),
            ],
            redacted_output="Contact <PERSON> at <EMAIL_ADDRESS> or call <PHONE_NUMBER>.",
            request_id="test-002",
        )
    )
    return scanner


def test_clean_output_returns_clean_status(client: TestClient):
    with patch("app.api.v1.audit._get_pii_scanner", return_value=_mock_scanner_clean()):
        response = client.post("/v1/audit", json=CLEAN_PAYLOAD)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "clean"
    assert data["pii_entities"] == []
    assert data["owasp_category"] == "LLM06"


def test_pii_output_is_detected_and_redacted(client: TestClient):
    with patch("app.api.v1.audit._get_pii_scanner", return_value=_mock_scanner_pii()):
        response = client.post("/v1/audit", json=PII_PAYLOAD)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pii_detected"
    assert len(data["pii_entities"]) == 2
    assert data["owasp_category"] == "LLM06"
    assert "<PERSON>" in data["redacted_output"]
    assert "<EMAIL_ADDRESS>" in data["redacted_output"]


def test_audit_response_contains_request_id(client: TestClient):
    with patch("app.api.v1.audit._get_pii_scanner", return_value=_mock_scanner_clean()):
        response = client.post("/v1/audit", json=CLEAN_PAYLOAD)

    assert response.json()["request_id"] == "test-001"


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
