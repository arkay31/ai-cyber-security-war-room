"""
Comprehensive tests for Ollama LLM Integration, RAG Retrieval,
Model Availability Validation, JSON Parsing Resilience, and Fallback Handling.
"""

import pytest
from unittest.mock import patch
from backend.app.services.llm_service import LLMService, llm_service
from backend.app.services.ai_analyst import ai_analyst
from backend.app.database import SessionLocal
from backend.app.models.incident import Incident


def test_ollama_availability_check():
    """Test 1: Check Ollama reachability and configured model presence."""
    is_ready = llm_service.check_availability()
    assert is_ready is True, "Local Ollama daemon with llama3 model should be reachable"


def test_model_availability_validation():
    """Test 2: Validate model name matching logic."""
    # Installed model matches
    assert llm_service.is_model_available("llama3") is True
    assert llm_service.is_model_available("llama3:latest") is True
    
    # Non-existent model must return False
    assert llm_service.is_model_available("non_existent_phantom_model_99") is False

    # Check check_availability returns False when model does not exist
    phantom_service = LLMService(model_name="non_existent_phantom_model_99")
    assert phantom_service.check_availability() is False


def test_direct_llm_generation_structured_json():
    """Test 3: Direct LLM generation through the backend service with JSON output."""
    prompt = "Generate a JSON object with keys 'status' (string 'ok') and 'verdict' (string 'malicious')."
    res = llm_service.generate(prompt=prompt, require_json=True, max_tokens=100)

    assert res["success"] is True
    assert res["status"] == "LLM"
    assert "llama3" in res["model"]
    assert isinstance(res["data"], dict)
    assert res["data"].get("status") == "ok" or "verdict" in res["data"]
    assert "latency" in res
    assert res["latency"] > 0


def test_json_parsing_resilience():
    """Test 4: Structured JSON parsing and auto-repair across tricky edge cases."""
    # Direct JSON
    assert llm_service._parse_json_safely('{"key": "value"}') == {"key": "value"}

    # Markdown code fence
    markdown_str = '```json\n{"technique": "T1110", "confidence": 0.95}\n```'
    assert llm_service._parse_json_safely(markdown_str) == {"technique": "T1110", "confidence": 0.95}

    # Conversational text surrounding JSON
    surrounded = 'Analysis complete:\n{"threat": "Credential Access"}\nPlease verify.'
    assert llm_service._parse_json_safely(surrounded) == {"threat": "Credential Access"}

    # Trailing commas cleanup
    trailing = '{"items": ["a", "b",], "score": 90,}'
    assert llm_service._parse_json_safely(trailing) == {"items": ["a", "b"], "score": 90}

    # Truncated string and unclosed object repair
    truncated = '{"summary": "Suspicious login from IP 10.0.0.1", "steps": ["Isolate host"'
    repaired = llm_service._parse_json_safely(truncated)
    assert repaired is not None
    assert repaired.get("summary") == "Suspicious login from IP 10.0.0.1"
    assert "Isolate host" in repaired.get("steps", [])


def test_invalid_json_fallback():
    """Test 5: Completely unparseable output correctly returns None."""
    assert llm_service._parse_json_safely("Plain text without any JSON or braces.") is None
    assert llm_service._parse_json_safely("") is None


def test_timeout_fallback():
    """Test 6: Inference timeout handling and graceful fallback to LLM_UNAVAILABLE."""
    # Service with impossibly small timeout (1 millisecond)
    fast_timeout_service = LLMService(timeout=0.001)
    res = fast_timeout_service.generate("Analyze this incident", require_json=True)

    assert res["success"] is False
    assert res["status"] == "LLM_UNAVAILABLE"
    assert "timed out" in res["error"].lower()
    assert res["data"] is None


def test_ollama_unavailable_fallback():
    """Test 7: Unreachable Ollama daemon handling."""
    unreachable_service = LLMService(base_url="http://127.0.0.1:59999")
    assert unreachable_service.check_availability() is False

    res = unreachable_service.generate("Test prompt")
    assert res["success"] is False
    assert res["status"] == "LLM_UNAVAILABLE"
    assert "unreachable" in res["error"].lower() or "refused" in res["error"].lower()


def test_full_rag_llm_investigation_workflow():
    """Test 8: Full SOC Incident investigation workflow with pgvector RAG + Ollama LLM."""
    with SessionLocal() as db:
        incident = db.query(Incident).order_by(Incident.id.desc()).first()
        assert incident is not None, "Need at least one incident in DB"

        res = ai_analyst.investigate(db, incident.id)

        assert res["status"] == "completed"
        # Since Ollama and model are running, it should produce LLM_RAG
        assert res["analysis_mode"] == "LLM_RAG"
        assert res["llm_status"] == "LLM_RAG"
        assert "llama3" in res["llm_model"]
        assert isinstance(res["confidence"], float)
        assert len(res["observed_evidence"]) > 0
        assert len(res["investigation_steps"]) > 0
        assert len(res["prioritized_recommendations"]) > 0
        assert len(res["evidence_references"]) > 0


def test_rule_based_fallback_integrity():
    """Test 9: Honest rule-based fallback when LLM is unavailable."""
    with SessionLocal() as db:
        incident = db.query(Incident).order_by(Incident.id.desc()).first()
        assert incident is not None

        # Temporarily mock check_availability to return False
        with patch.object(ai_analyst.llm, "check_availability", return_value=False):
            res = ai_analyst.investigate(db, incident.id)

            assert res["status"] == "completed"
            assert res["analysis_mode"] == "RULE_BASED"
            assert res["llm_status"] == "LLM_UNAVAILABLE"
            assert res["llm_model"] is None
            assert "RULE_BASED" in res["incident_summary"] or "LLM_UNAVAILABLE" in res["incident_summary"]
            assert "Rule-based analysis active" in res["analyst_warning"]
