"""
Tier 2 LLM provider abstraction layer for TriageMate.

DEPRECATED: All provider logic and orchestration live in pipeline/tier_2.py.
This module's helpers are superseded by pipeline/tier_2.py and remain here
only for backward compatibility. New code should import from pipeline.tier_2
directly.

Provides a unified interface for:
- OpenAI (gpt-4o-mini)
- Anthropic (claude-3-haiku)
- Together AI (mixtral-8x7b)

Used by pipeline/tier_2.py for LLM-based vulnerability analysis.

This module was extracted from pipeline/tier_2.py during Sprint 6 to separate
provider logic from the Tier 2 orchestration. The pipeline still retains inline
provider configuration for backward compatibility; this abstraction allows
new providers or call patterns to be added without modifying the pipeline.

Usage:
    from backend.integrations.llm import get_llm_provider, is_llm_available

    if is_llm_available():
        provider = get_llm_provider()  # "openai" | "anthropic" | "together"
        # ... proceed with LLM call
"""

import os
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider discovery
# ---------------------------------------------------------------------------


def get_llm_provider() -> Optional[str]:
    """Return the configured LLM provider name or *None* if unset.

    Reads ``TRIAGEMATE_LLM_PROVIDER`` from the environment; defaults to
    ``"openai"``.
    """
    return os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai").strip() or None


def get_llm_api_key() -> Optional[str]:
    """Return the configured LLM API key or *None* if unset.

    Reads ``TRIAGEMATE_LLM_API_KEY`` from the environment.
    """
    return os.getenv("TRIAGEMATE_LLM_API_KEY", "").strip() or None


def is_llm_available() -> bool:
    """Return *True* if an API key is configured and LLM calls can proceed."""
    return bool(get_llm_api_key())


def get_backup_provider() -> Optional[str]:
    """Return the backup LLM provider or *None* if unset.

    Reads ``TRIAGEMATE_LLM_BACKUP_PROVIDER`` from the environment.
    """
    return os.getenv("TRIAGEMATE_LLM_BACKUP_PROVIDER", "").strip() or None


def get_backup_api_key() -> Optional[str]:
    """Return the backup LLM API key or *None* if unset.

    Reads ``TRIAGEMATE_LLM_BACKUP_API_KEY`` from the environment.
    """
    return os.getenv("TRIAGEMATE_LLM_BACKUP_API_KEY", "").strip() or None


# ---------------------------------------------------------------------------
# Retry / backoff helpers
# ---------------------------------------------------------------------------


def retry_with_backoff(  # DEPRECATED: unused — retry logic is now inline in pipeline/tier_2.py provider functions.
    call_fn,
    max_retries: int = 3,
    base_delay: float = 1.0,
    backoff_factor: float = 2.0,
    logger: Optional[logging.Logger] = None,
) -> Any:
    """Execute *call_fn* with exponential backoff retry logic.

    Parameters
    ----------
    call_fn : callable
        A zero-argument callable that returns the desired result or raises
        an exception on failure.
    max_retries : int
        Maximum number of attempts (default 3).
    base_delay : float
        Initial delay in seconds (default 1.0).
    backoff_factor : float
        Multiplier applied to the delay after each failure (default 2.0).
    logger : logging.Logger or None
        Logger for recording retry events.

    Returns
    -------
    Any
        The return value of *call_fn* on success.

    Raises
    ------
    Exception
        The last exception raised by *call_fn* if all retries are exhausted.
    """
    _log = logger or logging.getLogger(__name__)
    last_exc = None

    for attempt in range(1, max_retries + 1):
        try:
            return call_fn()
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                delay = base_delay * (backoff_factor ** (attempt - 1))
                _log.warning(
                    "LLM call attempt %d/%d failed: %s. Retrying in %.1fs ...",
                    attempt,
                    max_retries,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                _log.error(
                    "LLM call failed after %d attempts: %s",
                    max_retries,
                    exc,
                )

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Provider-specific helpers
# ---------------------------------------------------------------------------

KNOWN_CONFLICTS: Dict[
    str, Dict[str, Any]
] = {  # DEPRECATED: use pipeline.tier_2.KNOWN_CONFLICTS instead. This module's version is unused.
    # Known CVE → neutral default scores used when LLM is unavailable
    # or when the CVE is part of the demo set.
    #
    # These ensure the pipeline never crashes on demo CVEs and provide
    # a zero-cost fallback when the LLM is unreachable.
}


def get_known_conflict(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return the known-conflict default for *cve_id*, or ``None``.

    This is a zero-cost fallback for demo CVEs to avoid unnecessary LLM
    calls during demonstration or testing.
    """
    return KNOWN_CONFLICTS.get(cve_id)
