"""
Centralized configuration for TriageMate pipeline constants.

Architecture rules:
- CENTRALIZE: Business-logic magic numbers that need regular tuning,
  and constants shared across 2+ modules
- KEEP LOCAL: Constants used in exactly one function or file
  (MAX_RETRIES in an API fetcher, formatting strings, feature encoders)

Moving single-use constants here forces you to jump between files
to understand a single function — that's worse than duplication.
"""

from pipeline.config.thresholds import *  # noqa: F403
from pipeline.config.scoring import *  # noqa: F403
from pipeline.config.feature_names import *  # noqa: F403
