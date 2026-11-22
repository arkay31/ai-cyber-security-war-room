import logging
import json
import time
from typing import Dict, Any, Optional
import httpx

from backend.app.services.llm_providers.base import BaseLLMProvider

logger = logging.getLogger(__name__)


class HostedAPIProvider(BaseLLMProvider):
    """
    OpenAI-compatible Hosted LLM API provider.
    Supports OpenAI (gpt-4o-mini, gpt-4o) and Groq (llama-3.3-70b-versatile, mixtral-8x7b-32768).
    """

    def __init__(
        self,
        provider_name: str,
        api_key: Optional[str],
        base_url: str,
        model: str,
        timeout: float = 60.0
    ):
        self._provider_name = provider_name.lower()
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._model = model
        self.timeout = timeout

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_name(self) -> str:
        return self._model

    def check_availability(self) -> bool:
        """Check if API key is present and endpoint responds."""
        if not self.api_key or self.api_key.strip() in ["", "your_openai_api_key_here", "your_groq_api_key_here"]:
            return False

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            with httpx.Client(timeout=4.0) as client:
                res = client.get(f"{self.base_url}/models", headers=headers)
                return res.status_code == 200
        except Exception as e:
            logger.debug(f"{self.provider_name} availability probe failed: {e}")
            return False

    def is_model_available(self, model_name: Optional[str] = None) -> bool:
        target = (model_name or self._model).strip().lower()
        if not self.api_key:
            return False
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            with httpx.Client(timeout=4.0) as client:
                res = client.get(f"{self.base_url}/models", headers=headers)
                if res.status_code == 200:
                    models = [m.get("id", "").lower() for m in res.json().get("data", [])]
                    return any(target in m for m in models)
        except Exception:
            pass
        return target == self._model.lower()

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        require_json: bool = True,
        temperature: float = 0.1,
        max_tokens: int = 600
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()

        if not self.api_key:
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"API key for {self.provider_name} is not configured.",
                "model": self._model,
                "data": None,
                "latency": 0.0
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        if require_json:
            payload["response_format"] = {"type": "json_object"}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                elapsed = round(time.perf_counter() - start_time, 3)

                if res.status_code != 200:
                    err_msg = f"{self.provider_name} returned HTTP {res.status_code}: {res.text[:120]}"
                    logger.warning(err_msg)
                    return {
                        "success": False,
                        "status": "LLM_UNAVAILABLE",
                        "error": err_msg,
                        "model": self._model,
                        "data": None,
                        "latency": elapsed
                    }

                data = res.json()
                raw_text = data["choices"][0]["message"]["content"].strip()

                usage = data.get("usage", {})
                metrics = {
                    "total_duration_sec": elapsed,
                    "prompt_eval_count": usage.get("prompt_tokens", 0),
                    "eval_count": usage.get("completion_tokens", 0),
                    "tokens_per_second": round(usage.get("completion_tokens", 0) / max(elapsed, 1e-4), 2)
                }

                parsed_data: Any = raw_text
                if require_json:
                    from backend.app.services.llm_service import LLMService
                    parsed_data = LLMService._parse_json_safely(raw_text)
                    if parsed_data is None:
                        return {
                            "success": False,
                            "status": "LLM",
                            "error": "Failed to parse structured JSON from hosted LLM response",
                            "model": self._model,
                            "raw_response": raw_text,
                            "data": None,
                            "latency": elapsed,
                            "metrics": metrics
                        }

                return {
                    "success": True,
                    "status": "LLM",
                    "data": parsed_data,
                    "model": self._model,
                    "error": None,
                    "latency": elapsed,
                    "metrics": metrics
                }

        except httpx.TimeoutException:
            elapsed = round(time.perf_counter() - start_time, 3)
            logger.warning(f"{self.provider_name} call timed out after {elapsed}s")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"Inference request timed out after {elapsed}s",
                "model": self._model,
                "data": None,
                "latency": elapsed
            }
        except Exception as e:
            elapsed = round(time.perf_counter() - start_time, 3)
            logger.error(f"{self.provider_name} request failed: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": str(e),
                "model": self._model,
                "data": None,
                "latency": elapsed
            }
