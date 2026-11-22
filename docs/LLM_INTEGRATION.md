# Polymorphic LLM Integration & AI Analyst Engine
## Aegis One – AI Cyber Security War Room

This document details the design, configuration, reliability mechanisms, and runtime behavior of the **Polymorphic LLM Engine** powering the Autonomous Tier-2 SOC Analyst in Aegis One.

---

## 1. Design Principles & Goals

1. **Local-First & Offline Capable**: Defaults to running entirely local via Ollama (`llama3:latest` 8B) for zero data leakage, privacy compliance, and offline demonstrations.
2. **Cloud-Agile**: Seamlessly switches to hosted high-throughput APIs (OpenAI `gpt-4o-mini`, Groq `llama-3.3-70b-versatile`) with a single environment variable change.
3. **Zero Disguise / Honest Labeling**: If the configured LLM is unreachable or times out, the system triggers a rule-based fallback and explicitly marks the analysis mode as `RULE_BASED` with `llm_status: "LLM_UNAVAILABLE"`. It **never** labels rule-based heuristics as model output.
4. **Structured JSON Validation**: All model outputs are strictly validated and backfilled using Pydantic's `AIInvestigationSchema`.

---

## 2. Polymorphic Architecture Diagram

```
                                  +-----------------------+
                                  |   AI Analyst Service  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |   LLMService Router   |
                                  +-----------+-----------+
                                              |
                 +----------------------------+----------------------------+
                 |                                                         |
                 v                                                         v
    [LLM_PROVIDER=ollama]                                     [LLM_PROVIDER=openai / groq]
+---------------------------------+                       +---------------------------------+
|         OllamaProvider          |                       |         HostedAPIProvider       |
|   (Local HTTP: /api/generate)   |                       |   (Chat Completions API)        |
+----------------+----------------+                       +----------------+----------------+
                 |                                                         |
                 v                                                         v
   +----------------------------+                            +----------------------------+
   |  Local Llama 3 (8B Q4)     |                            |  OpenAI gpt-4o-mini /      |
   |  Apple Silicon GPU Metal   |                            |  Groq Llama 3.3 70B        |
   +----------------------------+                            +----------------------------+
```

---

## 3. Configuration & Environment Variables

Configure the active provider in `backend/.env`:

### Option A: Local Ollama (Default & Offline)
```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=llama3
OLLAMA_TIMEOUT=120.0
```

### Option B: OpenAI (Cloud)
```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

### Option C: Groq (Ultra-Fast Inference)
```env
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_BASE_URL=https://api.groq.com/openai/v1
```

---

## 4. End-to-End Investigation Lifecycle

When an incident investigation is triggered (`POST /api/incidents/{id}/investigate`):

1. **Context Telemetry Gathering**: Collects events, timeline, risk score, and MITRE techniques.
2. **Machine Learning Attribution Injection**:
   - Computes local **TreeSHAP** feature importances on the primary incident flow.
   - Computes multivariate **Z-Score deviations** against the benign normal traffic baseline.
3. **RAG Vector Retrieval**: Searches PostgreSQL `pgvector` for matching playbooks with cosine similarity.
4. **Context Construction**: Injects telemetry, SHAP attributions, and retrieved playbooks into a single prompt with strict anti-hallucination directives.
5. **Inference Execution**: Dispatches to the active provider with JSON formatting mode enforced.
6. **Schema Validation & Repair**: Validates the payload against `AIInvestigationSchema`. If JSON contains markdown wrappers or trailing comments, safe regex extraction auto-repairs the response.
7. **Audit Logging**: Persists the complete prompt, response, latency, token metrics, and execution mode into the immutable `audit_logs` table.

---

## 5. Resilience & Fallback Guarantees

| Failure Scenario | System Handling | Resulting Status |
| :--- | :--- | :--- |
| **Ollama Daemon Offline** | Immediate catch during `check_availability()` | Falls back to rule-based analysis (`LLM_UNAVAILABLE`). |
| **Ollama Timeout (> 120s)** | `httpx.TimeoutException` caught | Logs timeout, activates rule-based analysis. |
| **Malformed JSON Output** | Multi-tier regex repair $\to$ Pydantic sanitizer | Extracts JSON snippet or cleanly backfills required keys. |
| **Cloud API Rate Limit / Error** | HTTP status code logging | Activates rule-based analysis without crashing backend. |
