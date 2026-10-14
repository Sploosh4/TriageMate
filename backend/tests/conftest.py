"""Current collection tests use explicit stores and synthetic transports."""

import os
import sys
from pathlib import Path

os.environ["TRIAGEMATE_SKIP_DOTENV"] = "true"
os.environ["TRIAGEMATE_LLM_API_KEY"] = ""

BACKEND = Path(__file__).resolve().parents[1]
for path in (BACKEND.parent, BACKEND):
    sys.path.insert(0, str(path))
