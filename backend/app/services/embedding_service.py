import os
import json
import logging
from typing import List, Optional
import numpy as np

from backend.app.config import settings

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Memory-conscious Embedding Service supporting precomputed cached embeddings,
    optional hosted OpenAI embeddings, and lazy-loaded SentenceTransformers.
    Designed to operate safely in memory-constrained (512 MiB) cloud environments.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self._model = None
        self._dimension = settings.EMBEDDING_DIMENSION
        self._cache = None

    def _get_cache(self) -> dict:
        """Lazy-load precomputed embeddings cache from disk if available."""
        if self._cache is None:
            self._cache = {}
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            cache_path = os.path.join(base_dir, "data", "knowledge", "precomputed_embeddings.json")
            if os.path.exists(cache_path):
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        self._cache = json.load(f)
                except Exception as e:
                    logger.debug(f"Precomputed embeddings cache not loaded: {e}")
        return self._cache

    @property
    def model(self):
        """Lazy-initialize SentenceTransformer with single-thread memory protection."""
        if self._model is None:
            try:
                # Restrict threads to keep memory footprint minimal in 512MiB containers
                os.environ["OMP_NUM_THREADS"] = "1"
                os.environ["MKL_NUM_THREADS"] = "1"
                os.environ["OPENBLAS_NUM_THREADS"] = "1"
                os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
                os.environ["NUMEXPR_NUM_THREADS"] = "1"

                try:
                    import torch
                    torch.set_grad_enabled(False)
                    torch.set_num_threads(1)
                    if hasattr(torch, "set_num_interop_threads"):
                        torch.set_num_interop_threads(1)
                except Exception:
                    pass

                from sentence_transformers import SentenceTransformer
                logger.info(f"Lazy-loading SentenceTransformer embedding model: {self.model_name}")
                try:
                    self._model = SentenceTransformer(self.model_name, local_files_only=True)
                except Exception:
                    self._model = SentenceTransformer(self.model_name)
            except Exception as e:
                logger.error(f"Failed to load SentenceTransformer model '{self.model_name}': {e}")
                raise RuntimeError(f"Embedding model initialization failed: {e}") from e
        return self._model

    def normalize_input(self, text: str) -> str:
        """Sanitize and normalize text input prior to embedding."""
        if not text:
            return ""
        return " ".join(text.strip().split())

    def _generate_hosted_embedding(self, text: str) -> Optional[List[float]]:
        """Attempt embedding generation using hosted OpenAI provider if configured."""
        if not settings.OPENAI_API_KEY:
            return None
        try:
            import httpx
            resp = httpx.post(
                f"{settings.OPENAI_BASE_URL}/embeddings",
                headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                json={
                    "input": text,
                    "model": "text-embedding-3-small",
                    "dimensions": self._dimension
                },
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["data"][0]["embedding"]
        except Exception as e:
            logger.warning(f"Hosted embedding generation failed: {e}")
        return None

    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate a normalized 384-dimensional dense vector for a single string.
        Prefers hosted provider if configured, then local SentenceTransformer,
        with graceful fallback if memory is constrained.
        """
        cleaned = self.normalize_input(text)
        if not cleaned:
            return [0.0] * self._dimension

        # 1. Check hosted provider if available
        if settings.OPENAI_API_KEY:
            hosted_emb = self._generate_hosted_embedding(cleaned)
            if hosted_emb:
                return hosted_emb

        # 2. Local SentenceTransformer with memory protection
        try:
            vector = self.model.encode(cleaned, normalize_embeddings=True)
            if isinstance(vector, np.ndarray):
                return vector.tolist()
            return list(vector)
        except (RuntimeError, MemoryError, Exception) as e:
            logger.error(f"Error generating embedding: {e}. Returning normalized zero vector fallback.")
            return [0.0] * self._dimension

    def batch_generate_embeddings(self, texts: List[str], batch_size: int = 16) -> List[List[float]]:
        """
        Generate normalized vector embeddings for a list of input texts.
        Uses smaller batch size (16) to conserve memory.
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
            return results


embedding_service = EmbeddingService()
