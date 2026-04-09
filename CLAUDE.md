# AI Firewall: Project Guidelines & Architecture

This document serves as the primary technical guide for the AI Firewall project. All development must adhere to the architectural decisions and coding standards outlined below.

## 1. Project Overview
The **AI Firewall** is a high-performance security microservice designed to protect Retrieval-Augmented Generation (RAG) systems. It focuses on mitigating **Indirect Prompt Injection (OWASP LLM01)** and **Sensitive Information Disclosure (OWASP LLM06)**.

## 2. Technical Stack
- **Framework:** FastAPI (Asynchronous Python 3.11+)
- **Security Logic:**
    - Tier 1: Vector-based similarity search (ChromaDB/Qdrant) for known malicious signatures.
    - Tier 2: LLM-as-a-Judge (Escalation logic for low-confidence detections).
    - Tier 3: Regex/PII Scanning (Microsoft Presidio) for output auditing.
- **Infrastructure:** Docker & Docker Compose.
- **Testing:** Pytest with high coverage requirements.

## 3. Repository Structure
```text
ai-firewall/
├── app/
│   ├── api/            # FastAPI routes (v1/sanitizer, v1/audit)
│   ├── core/           # Core logic (Vector engines, LLM Judge, PII logic)
│   ├── models/         # Pydantic schemas (Request/Response models)
│   ├── services/       # External service integrations (OpenAI/Azure/VectorDB)
│   └── main.py         # Application entry point
├── tests/              # Unit and Integration tests
├── docker/             # Dockerfiles and configuration
├── scripts/            # Utility scripts (Vector DB initialization)
├── .env.example        # Environment variables template
├── CLAUDE.md           # This file
└── README.md           # Project documentation
```

## 4. Coding Standards & Constraints
- **Asynchronous First:** Use `async/await` for all I/O bound operations (API calls, DB queries).
- **Type Safety:** Strict Python type hinting is mandatory.
- **Defensive Programming:**
    - Implement a "Dry Run" mode (`DRY_RUN=True`) where the firewall logs threats but returns `status: "allowed"`.
    - Fail-Safe Logic: Define behavior for when the LLM Judge is unreachable.
- **OWASP Alignment:** Every detection module must be mapped to an OWASP LLM category in the logs.

## 5. Development Commands
- **Install Dependencies:** `pip install -r requirements.txt`
- **Run Dev Server:** `uvicorn app.main:app --reload`
- **Run Tests:** `pytest`
- **Linting:** `flake8 app/`
- **Docker Build:** `docker-compose up --build`

## 6. Hybrid Detection Logic Workflow
1. **Input Receipt:** API receives prompt + retrieved context.
2. **Vector Check:** Search vector store for $sim(input, malicious\_payload) > \tau$.
3. **Conditional Escalation:** If similarity is in the "gray zone" (e.g., $0.6 < \tau < 0.8$), invoke LLM-as-a-Judge.
4. **Decision:** Return `block` or `allow` with a detailed `reasoning` object.
5. **Output Audit:** If allowed, scan LLM output for PII before final delivery.
