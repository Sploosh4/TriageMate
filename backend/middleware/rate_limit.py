"""
Rate limiting provider for TriageMate using slowapi.

Exports a shared Limiter instance and env-configurable limit strings
for per-route decorators.
"""

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Per-domain limits (overridable via env vars)
RATE_LIMIT_INGEST = os.getenv("RATE_LIMIT_INGEST", "10/minute")
RATE_LIMIT_ADMIN = os.getenv("RATE_LIMIT_ADMIN", "30/minute")
RATE_LIMIT_NOTES = os.getenv("RATE_LIMIT_NOTES", "60/minute")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "120/minute")
