"""
Tier 2 LLM evaluation package.

Provides multi-step agentic CVE investigation via tool-calling LLMs (Sprint 20),
with a fallback path to the single-shot evaluator.

The single-shot evaluator lives in single.py and is re-exported here for
backward compatibility with existing imports.
"""

# Re-export everything from the single-shot evaluator for backward compat
from pipeline.tier_2.single import (  # noqa: F401, E402
    # Configuration
    LLM_PROVIDER,
    LLM_API_KEY,
    LLM_MODEL,
    LLM_MAX_TOKENS,
    LLM_TIMEOUT,
    LLM_BASE_URL,
    BACKUP_PROVIDER,
    BACKUP_API_KEY,
    BACKUP_MODEL,
    # Feature flag
    AGENT_ENABLED,
    AGENT_MAX_STEPS,
    AGENT_COST_BUDGET,
    # Known conflicts
    KNOWN_CONFLICTS,
    TOGETHER_JSON_SCHEMA_MODELS,
    # Cost tracking
    _cost_tracking,
    _cost_lock,
    get_cost_tracking,
    _record_api_call,
    _compute_usage_dict,
    _COST_RATES,
    # Prompt building
    build_prompt,
    _SCHEMA_DESCRIPTION,
    # Provider functions
    call_openai,
    call_anthropic,
    call_together,
    _build_openai_schema,
    _build_anthropic_schema,
    _build_together_schema,
    _together_supports_json_schema,
    # Validation
    _validate_api_keys,
    # Main entry point
    evaluate_tier_2,
    _neutral_default,
    _MAX_RETRIES,
    _BASE_DELAY,
)

# New agentic modules
from pipeline.tier_2.tools import TOOL_DEFINITIONS, execute_tool, get_tool_names  # noqa: E402, F401
from pipeline.tier_2.agent import AgenticEvaluator  # noqa: E402, F401

__all__ = [
    "LLM_PROVIDER",
    "LLM_API_KEY",
    "LLM_MODEL",
    "LLM_MAX_TOKENS",
    "LLM_TIMEOUT",
    "LLM_BASE_URL",
    "AGENT_ENABLED",
    "AGENT_MAX_STEPS",
    "AGENT_COST_BUDGET",
    "KNOWN_CONFLICTS",
    "TOGETHER_JSON_SCHEMA_MODELS",
    "get_cost_tracking",
    "build_prompt",
    "call_openai",
    "call_anthropic",
    "call_together",
    "evaluate_tier_2",
    "TOOL_DEFINITIONS",
    "execute_tool",
    "get_tool_names",
    "AgenticEvaluator",
]
