"""
SBERT text encoder with PCA dimensionality reduction.

Encodes CVE description text into 32-dimensional vectors for
concatenation with the 37 tabular features in the Tier 1 XGBoost model.
"""

import numpy as np
import joblib
from pathlib import Path
from sentence_transformers import SentenceTransformer
from sklearn.decomposition import PCA

MODEL_DIR = Path(__file__).parent
SBERT_MODEL_NAME = "all-MiniLM-L6-v2"
PCA_COMPONENTS = 32
PCA_MODEL_FILE = MODEL_DIR / "pca_reducer.pkl"

_embedder = None
_pca = None


def _get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer(SBERT_MODEL_NAME, device="cpu")
    return _embedder


def _get_pca() -> PCA:
    global _pca
    if _pca is None:
        if PCA_MODEL_FILE.exists():
            _pca = joblib.load(PCA_MODEL_FILE)
        else:
            raise FileNotFoundError(
                f"PCA reducer not found at {PCA_MODEL_FILE}. "
                "Run fit_pca.py first to fit and save the PCA."
            )
    return _pca


def encode_description(description: str) -> np.ndarray:
    """Encode a single CVE description into a 32-dimensional vector."""
    embedder = _get_embedder()
    pca = _get_pca()
    embedding_384 = embedder.encode([description], show_progress_bar=False)
    embedding_32 = pca.transform(embedding_384)
    return embedding_32[0]


def encode_batch(descriptions: list[str]) -> np.ndarray:
    """Encode a batch of CVE descriptions. Returns (n_samples, 32)."""
    embedder = _get_embedder()
    pca = _get_pca()
    embeddings_384 = embedder.encode(descriptions, show_progress_bar=True)
    embeddings_32 = pca.transform(embeddings_384)
    return embeddings_32


def fit_pca(descriptions: list[str], save: bool = True) -> PCA:
    """
    Fit the PCA reducer on a corpus of CVE descriptions.
    Called once during the training pipeline, not at runtime.
    """
    embedder = _get_embedder()
    embeddings_384 = embedder.encode(descriptions, show_progress_bar=True)
    pca = PCA(n_components=PCA_COMPONENTS, random_state=42)
    pca.fit(embeddings_384)
    if save:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pca, PCA_MODEL_FILE)
        print(
            f"PCA fitted on {len(descriptions)} samples. "
            f"Variance preserved: {pca.explained_variance_ratio_.sum():.2%}. "
            f"Saved to {PCA_MODEL_FILE}"
        )
    global _pca
    _pca = pca
    return pca


def get_sbert_model():
    """Return the SBERT model directly (used by vector_store for document embeddings)."""
    return _get_embedder()
