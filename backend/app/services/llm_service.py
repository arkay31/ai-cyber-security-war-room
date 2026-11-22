import logging
import json
import re
import time
from typing import Dict, Any, Optional, List
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
        timeout: Optional[float] = None,
        provider: Optional[str] = None
    ):
        self.provider_type = (provider or getattr(settings, "LLM_PROVIDER", "ollama")).lower()
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model_name = model_name or (
            settings.OPENAI_MODEL if self.provider_type == "openai"
            else settings.GROQ_MODEL if self.provider_type == "groq"
            else settings.LLM_MODEL
        )
        self.timeout = timeout if timeout is not None else getattr(settings, "OLLAMA_TIMEOUT", 120.0)

        # Initialize hosted provider if configured
        self._hosted_provider = None
        if self.provider_type == "openai":
            from backend.app.services.llm_providers.hosted_provider import HostedAPIProvider
            self._hosted_provider = HostedAPIProvider(
                provider_name="openai",
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL,
                model=self.model_name,
                timeout=self.timeout
            )
        elif self.provider_type == "groq":
            from backend.app.services.llm_providers.hosted_provider import HostedAPIProvider
            self._hosted_provider = HostedAPIProvider(
                provider_name="groq",
                api_key=settings.GROQ_API_KEY,
                base_url=settings.GROQ_BASE_URL,
                model=self.model_name,
                timeout=self.timeout
            )

    def get_installed_models(self) -> List[Dict[str, Any]]:
        """Query Ollama daemon for installed models."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                if res.status_code == 200:
                    return res.json().get("models", [])
        except Exception as e:
            logger.debug(f"Failed to query Ollama tags at {self.base_url}: {e}")
        return []

    def is_model_available(self, model_name: Optional[str] = None) -> bool:
        """
        Check if a specific model (or self.model_name) is available.
        Delegates to hosted provider if configured, else checks Ollama.
        """
        if self._hosted_provider is not None:
            return self._hosted_provider.is_model_available(model_name)

        target = (model_name or self.model_name).strip()
        models = self.get_installed_models()
        if not models:
            return False

        installed_tags = [m.get("name", "") for m in models]
        installed_bases = [t.split(":")[0] for t in installed_tags]

        # 1. Exact match (e.g., 'llama3' == 'llama3' or 'llama3:latest' == 'llama3:latest')
        if target in installed_tags:
            return True
        # 2. Base tag match (e.g., target 'llama3' matches 'llama3:latest')
        if f"{target}:latest" in installed_tags:
            return True
        # 3. Base name match
        if target in installed_bases:
            return True

        return False

    def resolve_model_name(self) -> str:
        """Resolve model name to installed tag in Ollama if available."""
        models = self.get_installed_models()
        installed_tags = [m.get("name", "") for m in models]

        if self.model_name in installed_tags:
            return self.model_name
        if f"{self.model_name}:latest" in installed_tags:
            return f"{self.model_name}:latest"
        return self.model_name

    def check_availability(self) -> bool:
        """
        Check if configured inference service is reachable and model is available.
        Delegates to hosted provider if active, else probes local Ollama.
        """
        if self._hosted_provider is not None:
            return self._hosted_provider.check_availability()

        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                if res.status_code == 200:
                    data = res.json()
                    models = data.get("models", [])
                    installed_tags = [m.get("name", "") for m in models]
                    installed_bases = [t.split(":")[0] for t in installed_tags]

                    # Verify model availability
                    model_found = (
                        self.model_name in installed_tags
                        or f"{self.model_name}:latest" in installed_tags
                        or self.model_name in installed_bases
                    )

                    if model_found:
                        logger.info(
                            f"Ollama reachable at {self.base_url}. Model '{self.model_name}' verified. Installed: {installed_tags}"
                        )
                        return True
                    else:
                        logger.warning(
                            f"Ollama reachable at {self.base_url}, but configured model '{self.model_name}' is not installed! Available: {installed_tags}"
                        )
                        return False
        except httpx.ConnectError:
            logger.info(f"Ollama daemon not running or connection refused at {self.base_url}")
        except Exception as e:
            logger.debug(f"Ollama availability check failed at {self.base_url}: {e}")
        return False

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        require_json: bool = True,
        temperature: float = 0.1,
        max_tokens: int = 500
    ) -> Dict[str, Any]:
        """
        Send generation request to configured inference provider (Ollama or hosted API).
        Returns a dict indicating execution status conforming to War Room contract.
        """
        if self._hosted_provider is not None:
            return self._hosted_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                require_json=require_json,
                temperature=temperature,
                max_tokens=max_tokens
            )

        target_model = self.resolve_model_name()
        start_time = time.perf_counter()

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": 2048
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        if require_json:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/generate", json=payload)
                elapsed = round(time.perf_counter() - start_time, 3)

                if res.status_code != 200:
                    err_msg = f"Ollama returned HTTP {res.status_code}: {res.text[:120]}"
                    logger.warning(err_msg)
                    return {
                        "success": False,
                        "status": "LLM_UNAVAILABLE",
                        "error": err_msg,
                        "model": target_model,
                        "data": None,
                        "latency": elapsed
                    }

                resp_json = res.json()
                raw_text = resp_json.get("response", "").strip()

                # Extract performance metrics
                eval_count = resp_json.get("eval_count", 0)
                eval_duration_sec = resp_json.get("eval_duration", 0) / 1e9
                tps = round(eval_count / eval_duration_sec, 2) if eval_duration_sec > 0 else 0.0

                metrics = {
                    "total_duration_sec": elapsed,
                    "prompt_eval_count": resp_json.get("prompt_eval_count", 0),
                    "eval_count": eval_count,
                    "eval_duration_sec": round(eval_duration_sec, 3),
                    "tokens_per_second": tps
                }

                logger.info(
                    f"Ollama generation completed in {elapsed:.2f}s ({eval_count} tokens, {tps} tok/s) using model '{target_model}'"
                )

                if require_json:
                    parsed_data = self._parse_json_safely(raw_text)
                    if parsed_data is not None:
                        return {
                            "success": True,
                            "status": "LLM",
                            "model": target_model,
                            "data": parsed_data,
                            "raw": raw_text,
                            "latency": elapsed,
                            "metrics": metrics
                        }
                    else:
                        logger.warning(
                            f"Could not parse structured JSON from Ollama output ({len(raw_text)} chars). Snippet: {raw_text[:200]}"
                        )
                        return {
                            "success": False,
                            "status": "LLM_UNAVAILABLE",
                            "error": "Failed to parse structured JSON from LLM output",
                            "model": target_model,
                            "raw": raw_text,
                            "data": None,
                            "latency": elapsed,
                            "metrics": metrics
                        }

                return {
                    "success": True,
                    "status": "LLM",
                    "model": target_model,
                    "data": raw_text,
                    "latency": elapsed,
                    "metrics": metrics
                }

        except httpx.ConnectError as e:
            elapsed = round(time.perf_counter() - start_time, 3)
            logger.info(f"Ollama connection refused at {self.base_url}: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"Ollama not running or unreachable at {self.base_url}",
                "model": target_model,
                "data": None,
                "latency": elapsed
            }
        except httpx.TimeoutException as e:
            elapsed = round(time.perf_counter() - start_time, 3)
            logger.warning(f"Ollama request timed out after {self.timeout}s: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": f"Ollama inference timed out ({self.timeout}s)",
                "model": target_model,
                "data": None,
                "latency": elapsed
            }
        except Exception as e:
            elapsed = round(time.perf_counter() - start_time, 3)
            logger.error(f"Unexpected error during Ollama generation: {e}")
            return {
                "success": False,
                "status": "LLM_UNAVAILABLE",
                "error": str(e),
                "model": target_model,
                "data": None,
                "latency": elapsed
            }

    def _parse_json_safely(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Extract and parse JSON object from raw LLM text with resilience:
        1. Direct JSON parse
        2. Markdown block extraction ```json ... ```
        3. First { to last } slice with trailing-comma repair
        4. Truncation repair (closing unclosed quotes, brackets, and braces)
        """
        if not text or not text.strip():
            return None

        # 1. Direct parse attempt
        try:
            return json.loads(text)
        except Exception:
            pass

        # 2. Markdown block extraction ```(?:json)?\s*([\s\S]*?)\s*```
        block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if block_match:
            try:
                return json.loads(block_match.group(1))
            except Exception:
                pass

        # 3. Locate outermost {
        first_brace = text.find("{")
        if first_brace == -1:
            return None

        candidate = text[first_brace:]

        # If last brace exists, try slicing to last brace
        last_brace = candidate.rfind("}")
        if last_brace != -1:
            sub = candidate[:last_brace + 1]
            try:
                return json.loads(sub)
            except Exception:
                # Clean trailing commas: ,} or ,]
                cleaned = re.sub(r",\s*([}\]])", r"\1", sub)
                try:
                    return json.loads(cleaned)
                except Exception:
                    pass

        # 4. Truncation auto-repair: balance quotes, arrays, and object braces
        in_string = False
        escape = False
        stack = []

        for char in candidate:
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if char == "\"":
                in_string = not in_string
                continue
            if not in_string:
                if char in "{[":
                    stack.append("}" if char == "{" else "]")
                elif char in "}]":
                    if stack and stack[-1] == char:
                        stack.pop()

        repaired = candidate
        if in_string:
            repaired += "\""

        # Remove any trailing comma right before closing
        repaired = re.sub(r",\s*$", "", repaired)

        while stack:
            repaired += stack.pop()

        try:
            parsed = json.loads(repaired)
            logger.debug("Successfully repaired truncated JSON from LLM output")
            return parsed
        except Exception:
            # Try trailing comma fix on repaired string
            cleaned = re.sub(r",\s*([}\]])", r"\1", repaired)
            try:
                parsed = json.loads(cleaned)
                logger.debug("Successfully repaired truncated JSON with comma cleanup")
                return parsed
            except Exception:
                return None


llm_service = LLMService()
