"""
SecureBERT2.0-based CWE classifier.

Classifies CVE description text into the MITRE CWE taxonomy hierarchy.
Uses bziemba/SecureBERT2.0-final with multi-task learning heads.

Architecture: ModernBERT backbone + 4-layer MLP heads (LayerNorm→Linear→GELU→Linear→GELU→Linear)
for each CWE hierarchy level: pillar (10 classes), class (111), base (531), variant (292).

The model checkpoint has custom "cwe_heads.*" weights that standard AutoModel
ignores. We load them manually into a separate CWEHeads module and map class
indices to actual CWE IDs using the config's cwe_options.
"""

import json
import logging
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
from huggingface_hub import hf_hub_download

logger = logging.getLogger("triagemate.ml.cwe_classifier")

MODEL_NAME = "bziemba/SecureBERT2.0-final"

_tokenizer = None
_model = None
_cwe_heads = None
_cwe_id_map = {}  # group_name -> list of CWE IDs (index 0 -> CWE ID string)

CWE_HEAD_NAMES = ["cwe_pillar", "cwe_class", "cwe_base", "cwe_variant"]

_HEAD_GROUP_MAP = {
    "cwe_pillar": "pillar",
    "cwe_class": "class",
    "cwe_base": "base",
    "cwe_variant": "variant",
}

# Output dimensions from the trained checkpoint state dict
_CWE_NUM_CLASSES = {
    "pillar": 10,
    "class": 111,
    "base": 531,
    "variant": 292,
}


def _load_cwe_id_map():
    """Load the CWE options from the model config to build index→CWE-ID mappings."""
    global _cwe_id_map
    if _cwe_id_map:
        return _cwe_id_map

    try:
        config_path = hf_hub_download(MODEL_NAME, "config.json")
        with open(config_path) as f:
            config = json.load(f)

        # Note: the HF config uses "cwe_labels" (not "cwe_options")
        cwe_labels = config.get("cwe_labels") or config.get("cwe_options", {})
        for group in ["pillar", "class", "base", "variant"]:
            entries = cwe_labels.get(group, [])
            # Each entry: {"id": "284", "name": "Improper Access Control"}
            _cwe_id_map[group] = [entry["id"] for entry in entries]
            logger.debug(
                f"Loaded {len(_cwe_id_map[group])} CWE IDs for '{group}' "
                f"(first: CWE-{_cwe_id_map[group][0] if _cwe_id_map[group] else 'N/A'})"
            )
    except Exception as e:
        logger.warning(f"Failed to load CWE ID mapping from config: {e}")
        # Fallback: use index as CWE ID
        for group, count in _CWE_NUM_CLASSES.items():
            _cwe_id_map[group] = [str(i) for i in range(count)]

    return _cwe_id_map


class _CWEHeads(nn.Module):
    """Multi-layer CWE classification heads matching the SecureBERT2.0 architecture.

    Each head is a 4-layer network: LayerNorm → Linear → GELU → Linear → GELU → Linear
    (matching the original training code's layer indexing: 0, 2, 5, 8).
    """

    def __init__(self, hidden_size: int = 768):
        super().__init__()
        for group, num_classes in _CWE_NUM_CLASSES.items():
            # Architecture from trained checkpoint:
            #   0: LayerNorm(hidden_size) — weight/bias shape [768]
            #   2: Linear(hidden_size, hidden_size)
            #   5: Linear(hidden_size, hidden_size)
            #   8: Linear(hidden_size, num_classes)
            layers = nn.ModuleDict(
                {
                    "0": nn.LayerNorm(hidden_size),
                    "2": nn.Linear(hidden_size, hidden_size),
                    "5": nn.Linear(hidden_size, hidden_size),
                    "8": nn.Linear(hidden_size, num_classes),
                }
            )
            self.add_module(group, layers)

    def forward(self, group: str, x: torch.Tensor) -> torch.Tensor:
        layers = getattr(self, group)
        x = layers["0"](x)  # LayerNorm
        x = layers["2"](x)  # Linear
        x = torch.nn.functional.gelu(x)
        x = layers["5"](x)  # Linear
        x = torch.nn.functional.gelu(x)
        x = layers["8"](x)  # Linear (classifier head)
        return x


def _load_model():
    """Load the SecureBERT2.0 base model and CWE classification heads.

    Returns (tokenizer, base_model, cwe_heads_module, cwe_id_map).
    """
    global _tokenizer, _model, _cwe_heads

    if _model is not None:
        return _tokenizer, _model, _cwe_heads, _load_cwe_id_map()

    logger.info(
        "Loading SecureBERT2.0 tokenizer and base model (~656MB download if not cached)..."
    )
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    _model = AutoModel.from_pretrained(MODEL_NAME)
    _model.eval()

    # Build and load the CWE classification heads from the checkpoint state dict
    hidden_size = _model.config.hidden_size
    logger.info(f"Building CWE classification heads (hidden_size={hidden_size})...")
    _cwe_heads = _CWEHeads(hidden_size=hidden_size)

    # Load the full checkpoint and extract cwe_heads weights
    try:
        bin_path = hf_hub_download(MODEL_NAME, "pytorch_model.bin")
        checkpoint = torch.load(bin_path, map_location="cpu", weights_only=True)

        # Build a new state dict for _cwe_heads, stripping the "cwe_heads." prefix
        head_state = {}
        for k, v in checkpoint.items():
            if k.startswith("cwe_heads."):
                # e.g. "cwe_heads.pillar.0.weight" -> "pillar.0.weight"
                head_state[k[len("cwe_heads.") :]] = v

        _cwe_heads.load_state_dict(head_state, strict=True)
        _cwe_heads.eval()
        logger.info(
            f"CWE heads loaded successfully: "
            f"pillar={_CWE_NUM_CLASSES['pillar']}, "
            f"class={_CWE_NUM_CLASSES['class']}, "
            f"base={_CWE_NUM_CLASSES['base']}, "
            f"variant={_CWE_NUM_CLASSES['variant']} classes"
        )
    except Exception as e:
        logger.warning(
            f"Failed to load CWE head weights: {e}. All predictions will be 'Unknown'."
        )
        _cwe_heads = None

    # Pre-load the CWE ID mapping
    _load_cwe_id_map()

    return _tokenizer, _model, _cwe_heads, _cwe_id_map


def classify_cwe(text: str) -> dict:
    """
    Classify a CVE description into CWE hierarchy levels.

    Args:
        text: CVE description text (e.g. "Buffer overflow in network service
              allows remote code execution")

    Returns:
        dict with keys: cwe_pillar, cwe_class, cwe_base, cwe_variant.
        Each value is "CWE-XXX" (where XXX is the actual CWE ID from the
        MITRE taxonomy) or "Unknown".
    """
    tokenizer, model, heads, cwe_id_map = _load_model()
    inputs = tokenizer(
        text, return_tensors="pt", truncation=True, max_length=512, padding=True
    )

    with torch.no_grad():
        outputs = model(**inputs)
        cls_vector = outputs.last_hidden_state[:, 0, :]  # [1, 768]

    results = {}
    for head_name in CWE_HEAD_NAMES:
        group = _HEAD_GROUP_MAP[head_name]
        if heads is not None:
            try:
                logits = heads.forward(group, cls_vector)  # [1, num_classes]
                pred_index = torch.argmax(logits, dim=-1).item()

                # Map class index to actual CWE ID
                id_list = cwe_id_map.get(group, [])
                if 0 <= pred_index < len(id_list):
                    cwe_id = id_list[pred_index]
                    results[head_name] = f"CWE-{cwe_id}"
                else:
                    results[head_name] = "Unknown"
            except Exception as e:
                logger.warning(f"CWE head '{head_name}' prediction failed: {e}")
                results[head_name] = "Unknown"
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
