"""
SecureBERT2.0-based CWE classifier.

Classifies CVE description text into the MITRE CWE taxonomy hierarchy.
Uses bziemba/SecureBERT2.0-final with 12 multi-task learning heads.
"""

import torch
from transformers import AutoTokenizer, AutoModel
from pathlib import Path

MODEL_NAME = "bziemba/SecureBERT2.0-final"
MODEL_DIR = Path(__file__).parent / "securebert_cache"

_tokenizer = None
_model = None

CWE_HEAD_NAMES = ["cwe_pillar", "cwe_class", "cwe_base", "cwe_variant"]


def _load_model():
    global _tokenizer, _model
    if _model is None:
        _tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME, cache_dir=str(MODEL_DIR))
        _model = AutoModel.from_pretrained(
            MODEL_NAME, cache_dir=str(MODEL_DIR))
        _model.eval()
    return _tokenizer, _model


def classify_cwe(text: str) -> dict:
    """
    Classify a CVE description into CWE hierarchy levels.

    Returns dict with keys: cwe_pillar, cwe_class, cwe_base, cwe_variant.
    """
    tokenizer, model = _load_model()
    inputs = tokenizer(
        text, return_tensors="pt", truncation=True,
        max_length=512, padding=True
    )

    with torch.no_grad():
        outputs = model(**inputs)
        pooled = outputs.pooler_output

    results = {}
    for i, head_name in enumerate(CWE_HEAD_NAMES):
        head = getattr(model, f"cwe_head_{i}", None)
        if head is not None:
            logits = head(pooled)
            pred_class = torch.argmax(logits, dim=-1).item()
            results[head_name] = (
                f"CWE-{pred_class}" if pred_class > 0 else "Unknown"
            )
        else:
            results[head_name] = "Unknown"

    return results


def get_cwe_class(text: str) -> str:
    """Return the CWE Class level for RAG query construction."""
    result = classify_cwe(text)
    return result.get("cwe_class", "Unknown")


def get_cwe_for_rag(text: str) -> str:
    """Return a human-readable CWE description for RAG query construction."""
    cwe = get_cwe_class(text)
    if cwe == "Unknown":
        return "unknown vulnerability class"
    return cwe
