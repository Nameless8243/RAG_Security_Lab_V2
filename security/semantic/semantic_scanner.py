# security/semantic/semantic_scanner.py

import numpy as np
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer
from numpy.linalg import norm


class SemanticScanner:
    """
    SemanticScanner V3 – REAL semantic embeddings

    Features:
      - SentenceTransformer real embeddings (MiniLM-L6-v2)
      - Cosine distance scoring
      - Baseline centroid from reference embeddings
      - Reliable semantic anomaly detection
    """

    def __init__(
        self,
        reference_texts: Optional[List[str]] = None,
        semantic_threshold: float = 0.35,
        alpha: float = 0.6,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        """
        :param reference_texts: optional list of clean baseline documents
        :param semantic_threshold: threshold for total_score anomaly
        :param alpha: weight for (semantic_score vs cluster_distance)
        """
        self.model = SentenceTransformer(model_name)
        self.semantic_threshold = semantic_threshold
        self.alpha = alpha

        # Build reference embeddings
        if reference_texts is None:
            reference_texts = ["Default clean baseline policy text."]
        self.reference_embeddings = self._embed_texts(reference_texts)

        # Precompute centroid
        self.baseline_centroid = np.mean(self.reference_embeddings, axis=0)

    # ------------------------------------------------------------

    def _embed_texts(self, texts: List[str]) -> np.ndarray:
        """
        Encode a list of texts into normalized embeddings.
        """
        emb = self.model.encode(texts, convert_to_numpy=True)
        emb = emb / np.clip(norm(emb, axis=1, keepdims=True), 1e-8, None)
        return emb

    def _embed(self, text: str) -> np.ndarray:
        """
        Encode a single text into a normalized embedding.
        """
        emb = self.model.encode([text], convert_to_numpy=True)[0]
        emb = emb / max(norm(emb), 1e-8)
        return emb

    # ------------------------------------------------------------

    @staticmethod
    def cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
        """
        Cosine distance = 1 - cosine similarity.
        """
        return float(1 - np.dot(a, b))

    # ------------------------------------------------------------

    def compute_scores(self, doc_embedding: np.ndarray) -> Dict[str, float]:
        """
        Compute semantic anomaly scores.
        """
        semantic_score = self.cosine_distance(doc_embedding, self.baseline_centroid)

        cluster_dists = [
            self.cosine_distance(doc_embedding, ref) for ref in self.reference_embeddings
        ]
        cluster_distance = float(np.mean(cluster_dists))

        total_score = self.alpha * semantic_score + (1 - self.alpha) * cluster_distance

        return {
            "semantic_score": semantic_score,
            "cluster_distance": cluster_distance,
            "total_score": total_score,
            "is_suspicious": total_score > self.semantic_threshold,
        }

    # ------------------------------------------------------------

    def detect(self, document_text: str, reference_texts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform full semantic anomaly detection.
        """
        if reference_texts is not None:
            self.reference_embeddings = self._embed_texts(reference_texts)
            self.baseline_centroid = np.mean(self.reference_embeddings, axis=0)

        doc_emb = self._embed(document_text)
        return self.compute_scores(doc_emb)
