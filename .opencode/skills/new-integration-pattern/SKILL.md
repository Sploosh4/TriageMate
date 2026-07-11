---
name: new-integration-pattern
description: Boilerplate template for adding a new threat intel / enrichment source to TriageMate
---

# New Integration Pattern

## GitHub Workflow

Test `gh` access before relying on it. Use subagent operations when Level 4+ verified; otherwise route mutations through the commander.

## The 4-step pipeline
```
integrations/<name>.py  →  ingest_helpers.py (import + call)  →  build_feature_vector()  →  training corpus
```

## Step 1 — Create the integration module
Create `backend/integrations/<name>.py` following this skeleton:
```python
"""
<Name> client.  <auth notes>.  Independently skippable — fails gracefully to safe defaults.
"""
import time, logging
logger = logging.getLogger("triagemate.<name>")
_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 3600

def query_<name>(cve_id: str) -> dict:
    now = time.time()
    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < CACHE_TTL:
            return dict(data)
    try:
        # API call
        result = {"queried": True, ...}
        _CACHE[cve_id] = (now, result)
        return dict(result)
    except Exception as e:
        logger.warning("<name> query failed for %s: %s", cve_id, e)
        result = {"queried": False, ...}
        _CACHE[cve_id] = (now, result)
        return dict(result)
```

## Step 2 — Register in ingest_helpers.py
Add import at the top:
```python
from integrations.<name> import query_<name>
```

## Step 3 — Slot into build_feature_vector()
Call alongside existing integrations (~line 414) and add 1-3 feature keys to the returned dict.

## Step 4 — Regenerate training corpus
```bash
python backend/scripts/build_training_corpus.py
```

## Reference
See `backend/integrations/osv.py` for a clean real example of this pattern.
