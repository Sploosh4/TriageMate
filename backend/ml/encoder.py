"""
SBERT text encoder — raw 384-dimensional embeddings.

Encodes CVE description text into 384-dimensional vectors for
concatenation with the 35 tabular features in the Tier 1 XGBoost model.
PCA has been removed (v2.5) to eliminate data leakage — PCA was fitted
on ALL data (including test set) before any split. XGBoost handles the
full 384-dim space with built-in regularization (colsample_bytree=0.8,
max_depth=4).
"""

import logging
import threading

import numpy as np
import requests
from pathlib import Path
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("triagemate.encoder")

MODEL_DIR = Path(__file__).parent
SBERT_MODEL_NAME = "all-MiniLM-L6-v2"
SBERT_DIM = 384

_embedder = None
_lock = threading.Lock()


def _get_embedder() -> SentenceTransformer | None:
    global _embedder
    if _embedder is None:
        with _lock:
            if _embedder is None:
                try:
                    _embedder = SentenceTransformer(SBERT_MODEL_NAME, device="cpu")
                except (
                    OSError,
                    ConnectionError,
                    requests.exceptions.ConnectionError,
                ) as e:
                    logger.error("SBERT download failed: %s — using zero vectors", e)
                    _embedder = None
    return _embedder


def encode_description(description: str) -> np.ndarray:
    """Encode a single CVE description into a 384-dimensional vector."""
    embedder = _get_embedder()
    if embedder is None:
        return np.zeros(SBERT_DIM, dtype=np.float32)
    embedding = embedder.encode([description], show_progress_bar=False)
    return embedding[0]


def encode_batch(descriptions: list[str]) -> np.ndarray:
    """Encode a batch of CVE descriptions. Returns (n_samples, 384)."""
    embedder = _get_embedder()
    if embedder is None:
        return np.zeros((len(descriptions), SBERT_DIM), dtype=np.float32)
    embeddings = embedder.encode(descriptions, show_progress_bar=True)
    return embeddings


def get_sbert_model():
    """Return the SBERT model directly (used by vector_store for document embeddings)."""
    return _get_embedder()
