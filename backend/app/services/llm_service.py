import logging
import json
import re
from typing import Dict, Any, Optional
import httpx

from backend.app.config import settings

logger = logging.getLogger(__name__)


class LLMService:
    """
    LLM service targeting local Ollama inference with structured JSON outputs.
    Guarantees strict labeling (LLM, LLM_RAG, or LLM_UNAVAILABLE).
    Never disguises rule-based outputs as LLM generations.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: float = 90.0
    ):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model_name = model_name or settings.LLM_MODEL
        self.timeout = timeout

    def check_availability(self) -> bool:
        """Check if local Ollama daemon is reachable and responding."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                if res.status_code == 200:
                    data = res.json()
                    models = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
                    logger.info(f"Ollama reachable. Available models: {models}")
                    return True
        except Exception as e:
            logger.debug(f"Ollama availability check failed: {e}")
        return False

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        require_json: bool = True,
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        """
        Send generation request to Ollama.
        Returns a dict indicating execution status:
        - status: "LLM" or "LLM_UNAVAILABLE"
        - success: bool
        - response: parsed dict or raw text
        - error: Optional[str]
        """
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 600,
                "num_ctx": 4096
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        if require_json:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/generate", json=payload)

                if res.status_code != 200:
                    logger.warning(f"Ollama returned HTTP {res.status_code}: {res.text}")
                    return {
                        "success": False,
                        "status": "LLM_UNAVAILABLE",
                        "error": f"Ollama returned HTTP {res.status_code}",
                        "model": self.model_name,
                        "data": None
                    }

                resp_json = res.json()
                raw_text = resp_json.get("response", "").strip()

                if require_json:
                    parsed_data = self._parse_json_safely(raw_text)
                    if parsed_data is not None:
                        return {
                            "success": True,
                            "status": "LLM",
                            "model": self.model_name,
                            "data": parsed_data,
                            "raw": raw_text
                        }
                    else:
                        logger.warning(f"Could not parse JSON from Ollama response: {raw_text[:200]}")
                        return {
                            "success": False,
                            "status": "LLM_UNAVAILABLE",
                            "error": "Failed to parse structured JSON from LLM output",
                            "model": self.model_name,
                            "raw": raw_text,
                            "data": None
                        }

                return {
                    "success": True,
                    "status": "LLM",
                    "model": self.model_name,
                    "data": raw_text
                }

        except httpx.ConnectError as e:
            logger.info(f"Ollama connection refused at {self.base_url}: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"Ollama not running or unreachable at {self.base_url}",
                "model": self.model_name,
                "data": None
            }
        except httpx.TimeoutException as e:
            logger.warning(f"Ollama request timed out after {self.timeout}s: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"Ollama inference timed out ({self.timeout}s)",
                "model": self.model_name,
                "data": None
            }
        except Exception as e:
            logger.error(f"Unexpected error during Ollama generation: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": str(e),
                "model": self.model_name,
                "data": None
            }

    def _parse_json_safely(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract and parse JSON object from raw LLM text."""
        # 1. Direct parse attempt
        try:
            return json.loads(text)
        except Exception:
            pass

        # 2. Markdown block extraction ```json ... ```
        block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if block_match:
            try:
                return json.loads(block_match.group(1))
            except Exception:
                pass

        # 3. First brace to last brace extraction
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(text[first_brace:last_brace + 1])
            except Exception:
                pass

        return None


llm_service = LLMService()
