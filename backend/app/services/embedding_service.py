import logging
from typing import List, Optional
import numpy as np

from backend.app.config import settings

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Embedding service supporting local SentenceTransformers models
    with configurable model name and optional OpenAI embedding fallback.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self._model = None
        self._dimension = settings.EMBEDDING_DIMENSION

    @property
    def model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                logger.info(f"Loading SentenceTransformer embedding model: {self.model_name}")
                self._model = SentenceTransformer(self.model_name)
            except Exception as e:
                logger.error(f"Failed to load SentenceTransformer model '{self.model_name}': {e}")
                raise RuntimeError(f"Embedding model initialization failed: {e}") from e
        return self._model

    def normalize_input(self, text: str) -> str:
        """Sanitize and normalize text input prior to embedding."""
        if not text:
            return ""
        # Clean up repeated whitespace and newlines
        cleaned = " ".join(text.strip().split())
        return cleaned

    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate a normalized 384-dimensional dense vector for a single string.
        """
        cleaned = self.normalize_input(text)
        if not cleaned:
            # Return zero vector if text is empty
            return [0.0] * self._dimension

        try:
            vector = self.model.encode(cleaned, normalize_embeddings=True)
            if isinstance(vector, np.ndarray):
                return vector.tolist()
            return list(vector)
        except Exception as e:
            logger.error(f"Error generating embedding for input text: {e}")
            raise

    def batch_generate_embeddings(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Generate normalized vector embeddings for a list of input texts.
        """
        cleaned_texts = [self.normalize_input(t) for t in texts]
        non_empty_indices = [i for i, t in enumerate(cleaned_texts) if len(t) > 0]

        results: List[List[float]] = [[0.0] * self._dimension for _ in texts]
        if not non_empty_indices:
            return results

        texts_to_encode = [cleaned_texts[i] for i in non_empty_indices]

        try:
            vectors = self.model.encode(
                texts_to_encode,
                batch_size=batch_size,
                show_progress_bar=False,
                normalize_embeddings=True
            )
            for idx, vec in zip(non_empty_indices, vectors):
                if isinstance(vec, np.ndarray):
                    results[idx] = vec.tolist()
                else:
                    results[idx] = list(vec)
            return results
        except Exception as e:
            logger.error(f"Error generating batch embeddings: {e}")
            raise


embedding_service = EmbeddingService()
