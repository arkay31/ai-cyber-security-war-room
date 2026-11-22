from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseLLMProvider(ABC):
    """
    Abstract interface for LLM inference providers.
    Supports both local offline inference (Ollama) and hosted cloud APIs (OpenAI, Groq).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier for the provider (e.g., 'ollama', 'openai', 'groq')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Active model name identifier."""
        pass

    @abstractmethod
    def check_availability(self) -> bool:
        """Verify reachability and readiness of the provider and configured model."""
        pass

    @abstractmethod
    def is_model_available(self, model_name: Optional[str] = None) -> bool:
        """Verify whether a specific model name is available on the provider."""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        require_json: bool = True,
        temperature: float = 0.1,
        max_tokens: int = 500
    ) -> Dict[str, Any]:
        """
        Execute generation request.
        Returns a dictionary conforming to the standard War Room contract:
        {
            "status": "LLM" | "LLM_UNAVAILABLE",
            "success": bool,
            "data": dict | str,
            "model": str,
            "latency": float,
            "metrics": dict,
            "error": Optional[str]
        }
        """
        pass
