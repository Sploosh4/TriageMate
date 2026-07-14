"""
Tier 2: Semantic Analysis via Cloud-Hosted Language Model.

This stage receives cases that Tier 0 and Tier 1 could not confidently resolve.
It sends the CVE description, upstream scores, and asset context to a cloud LLM
API that runs the adversarial force-reflection loop. The API returns a structured
JSON response with the conflict assessment and final resolution.

Supported providers (configured via environment variable):
- OpenAI (gpt-4o-mini recommended for MVP cost optimization)
- Anthropic (claude-haiku-4-5 recommended for MVP cost optimization)
- Together AI (hosted open-weight models)
"""

import os
import json
import logging
import asyncio
import threading
from pathlib import Path
from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

logger = logging.getLogger("triagemate.tier_2")

# Provider configuration from environment
LLM_PROVIDER = os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai")
LLM_API_KEY = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
LLM_MODEL = os.getenv("TRIAGEMATE_LLM_MODEL", "gpt-4o-mini")
LLM_MAX_TOKENS = int(os.getenv("TRIAGEMATE_LLM_MAX_TOKENS", "1024"))
LLM_TIMEOUT = int(os.getenv("TRIAGEMATE_LLM_TIMEOUT", "30"))
LLM_BASE_URL = os.getenv("TRIAGEMATE_LLM_BASE_URL", "https://api.openai.com/v1")

# Agent feature flag — Sprint 20: Multi-Step Agentic LLM
# When enabled, uses AgenticEvaluator with tool-calling loop instead of single-shot prompt.
AGENT_ENABLED = os.getenv("TRIAGEMATE_AGENT_ENABLED", "").lower() == "true"
AGENT_MAX_STEPS = int(os.getenv("TRIAGEMATE_AGENT_MAX_STEPS", "15"))
AGENT_COST_BUDGET = float(os.getenv("TRIAGEMATE_AGENT_COST_BUDGET", "0.50"))

BACKUP_PROVIDER = os.getenv("TRIAGEMATE_LLM_BACKUP_PROVIDER", "")
BACKUP_API_KEY = os.getenv("TRIAGEMATE_LLM_BACKUP_API_KEY", "")
BACKUP_MODEL = os.getenv("TRIAGEMATE_LLM_BACKUP_MODEL", "")

_MAX_RETRIES = 3
_BASE_DELAY = 1.0

# Together AI models known to support json_schema response_format
# https://docs.together.ai/docs/json-mode
TOGETHER_JSON_SCHEMA_MODELS = frozenset(
    {
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "Qwen/Qwen3.5-9B",
        "Qwen/Qwen3.5-32B",
    }
)

# Known conflict resolutions — used as fallback when API is unavailable
KNOWN_CONFLICTS = {
    "CVE-2023-36884": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: Active exploitation confirmed, "
            "weaponised in spear-phishing targeting government social services. "
            "Negative constraint: Microsoft advisory states registry key mitigation "
            "blocks attack vector. RAG search returned conflicting GPO deployment "
            "records — ASR rule may or may not be active on this endpoint."
        ),
        "rag_result": "UNCERTAIN",
        "resolution": "Exploitability signal dominates. Mitigation status unverifiable. "
        "Assign score 63 — Critical band. Flag for manual ASR verification.",
        "confidence": 0.72,
        "score_adjustment": -15,
    },
    "CVE-2023-22515": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: CVSS 10.0, CISA KEV, actively exploited "
            "by nation-state groups targeting law enforcement Confluence instances. "
            "Negative constraint: Change record CM-2023-10287 documents successful "
            "upgrade to 8.5.2, but scanner still fingerprints 8.5.1. RAG search "
            "revealed hostname alias confusion with staging server PRD-WIKI-CORE02."
        ),
        "rag_result": "UNCERTAIN",
        "resolution": "Scanner evidence carries more weight than change record. "
        "Assign score 41 — Medium band. ICT team demonstrated awareness "
        "within 14 days, reducing urgency.",
        "confidence": 0.68,
        "score_adjustment": -37,
    },
    "CVE-2022-47966": {
        "text_conflict": True,
        "conflict_note": (
            "Primary exploitability assessment: CVSS 9.8, pre-auth RCE, multiple "
            "public PoCs, CISA KEV, exploited by APT groups. Tier 0 did not auto-resolve "
            "because ManageEngine spans 24 products with varying SAML profiles. "
            "Negative constraint: RAG search confirmed SAML SSO is explicitly disabled "
            "(saml.sso.enabled=false) with LDAP-only authentication. "
            "/SamlResponseServlet returns 404."
        ),
        "rag_result": "CONFIRMED",
        "resolution": "SAML-disabled configuration eliminates attack surface. "
        "Assign score 22 — Low band. Persistent flag to alert if "
        "SAML is ever enabled. Recommend patching to remove vulnerable libraries.",
        "confidence": 0.91,
        "score_adjustment": -66,
    },
}

# Cost tracking — module-level accumulators
_cost_lock = threading.Lock()
_cost_tracking = {
    "total_calls": 0,
    "total_input_tokens": 0,
    "total_output_tokens": 0,
    "total_cached_tokens": 0,
    "estimated_cost_usd": 0.0,
}

# Approximate per-1M-token pricing (model-specific, used for estimation)
_COST_RATES = {
    "openai": {"input": 0.15, "output": 0.60},
    "anthropic": {"input": 0.25, "output": 1.25},
    "together": {"input": 0.20, "output": 0.20},
}


def get_cost_tracking() -> dict:
    """Return a snapshot of the cost tracking accumulators."""
    return dict(_cost_tracking)


def _validate_api_keys():
    """Warn if API keys appear malformed. Doesn't block."""
    if LLM_API_KEY:
        if LLM_PROVIDER == "anthropic" and not LLM_API_KEY.startswith("sk-ant-api03-"):
            logger.warning(
                "Anthropic API key doesn't match expected prefix 'sk-ant-api03-'"
            )
        elif LLM_PROVIDER == "openai" and not (
            LLM_API_KEY.startswith("sk-") or LLM_API_KEY.startswith("sk-proj-")
        ):
            logger.warning(
                "OpenAI API key doesn't match expected prefix 'sk-' or 'sk-proj-'"
            )
    if BACKUP_API_KEY:
        if BACKUP_PROVIDER == "anthropic" and not BACKUP_API_KEY.startswith(
            "sk-ant-api03-"
        ):
            logger.warning(
                "Backup Anthropic API key doesn't match expected prefix 'sk-ant-api03-'"
            )
        elif BACKUP_PROVIDER == "openai" and not (
            BACKUP_API_KEY.startswith("sk-") or BACKUP_API_KEY.startswith("sk-proj-")
        ):
            logger.warning(
                "Backup OpenAI API key doesn't match expected prefix 'sk-' or 'sk-proj-'"
            )


# Validate once at import time
_validate_api_keys()


# ---------------------------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------------------------

_SCHEMA_DESCRIPTION = """{
  "text_conflict": true or false,
  "conflict_note": "Plain-English explanation of the conflict (max 300 chars).",
  "rag_result": "UNCERTAIN if ambiguous, CONFIRMED if verified, NOT_NEEDED if no conflict.",
  "resolution": "Resolution recommendation (max 500 chars).",
  "confidence": float 0.0-1.0,
  "score_adjustment": integer -20 to +20
}"""


def build_prompt(
    cve_id: str,
    cvss_score: float,
    description: str,
    rag_context: str,
    cisa_kev: bool,
    epss_score: float,
    cvss_vector: str,
    upstream_scores: dict,
    mission_tags: dict,
    cwe_result: dict | None = None,
) -> tuple[str, str]:
    """Build the force-reflection prompt for the cloud LLM.

    Returns (system_content, user_content) for use in message-based APIs.
    System content is static (cacheable); user content is dynamic per request.
    """

    system_content = (
        "You are a vulnerability prioritization analyst for the Western Australian "
        "government. Analyze this vulnerability and determine whether a text conflict "
        "exists between the exploitability signals and any mitigating constraints.\n\n"
        "Perform the following analysis:\n\n"
        "Step A — Primary Exploitability Assessment:\n"
        "Based on the CVE description, CVSS score, threat intelligence feeds (CISA KEV status "
        "is implicitly reflected in the upstream scores), and the asset context, assess whether "
        "this vulnerability presents a credible, exploitable threat to this specific asset.\n\n"
        "Step B — Counter-Argument:\n"
        "Identify any negative constraints in the vulnerability advisory or asset configuration "
        "that could nullify or reduce the exploitability. Consider: non-default settings required, "
        "mitigation already in place, attack surface not reachable, user interaction requirements, "
        "privilege prerequisites.\n\n"
        "Step C — Final Determination:\n"
        "Weigh the primary assessment against the counter-argument. Determine whether a text "
        "conflict exists (where the exploitability signal and the mitigating constraint are in "
        "tension and cannot be definitively resolved without human investigation).\n\n"
        f"Return your analysis as a JSON object with exactly these fields:\n"
        f"{_SCHEMA_DESCRIPTION}\n\n"
        "Reply with ONLY the JSON object. No preamble, no explanation, no markdown fences."
    )

    cwe_block = ""
    if cwe_result:
        cwe_block = (
            f"- CWE Pillar: {cwe_result.get('cwe_pillar', 'Unknown')}\n"
            f"- CWE Class: {cwe_result.get('cwe_class', 'Unknown')}\n"
            f"- CWE Base: {cwe_result.get('cwe_base', 'Unknown')}\n"
            f"- CWE Variant: {cwe_result.get('cwe_variant', 'Unknown')}\n"
        )

    user_content = (
        f"CVE ID: {cve_id}\n"
        f"CVSS Score: {cvss_score}\n"
        f"CISA KEV: {cisa_kev}\n"
        f"EPSS Score: {epss_score}\n"
        f"CVSS Vector: {cvss_vector}\n"
        f"Description: {description}\n\n"
        f"Asset Context:\n"
        f"- Mission Prevalence: {mission_tags.get('mission_prevalence', 'Unknown')}\n"
        f"- Public Well-Being Impact: {mission_tags.get('public_wellbeing_impact', 'Unknown')}\n\n"
        f"CWE Classification:\n{cwe_block}"
        f"RAG Context:\n{rag_context}\n\n"
        f"Upstream Tier 1 Scores:\n"
        f"- Exploitation Probability: {upstream_scores.get('exploitation_probability', 'N/A')}\n"
        f"- Model Confidence: {upstream_scores.get('confidence', 'N/A')}"
    )

    return system_content, user_content


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------


def _build_openai_schema() -> dict:
    """Build the OpenAI json_schema response_format from TriageConflictResult."""
    from models import TriageConflictResult

    schema = TriageConflictResult.model_json_schema()
    schema["additionalProperties"] = False
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "triage_conflict",
            "strict": True,
            "schema": schema,
        },
    }


async def call_openai(
    system_content: str, user_content: str, api_key: str, model: str
) -> tuple[dict, dict]:
    """Call OpenAI Chat Completions with json_schema response format.

    Uses json_schema mode (not json_object) for schema-enforced output.
    Handles refusals (content_filter finish_reason).
    """
    import httpx

    timeout = httpx.Timeout(LLM_TIMEOUT, connect=10.0)
    schema = _build_openai_schema()

    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{LLM_BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_content},
                            {"role": "user", "content": user_content},
                        ],
                        "temperature": 0.1,
                        "max_tokens": LLM_MAX_TOKENS,
                        "response_format": schema,
                    },
                )
                response.raise_for_status()
                data = response.json()
                choice = data["choices"][0]
                message = choice["message"]

                # Check for refusal
                if choice.get("finish_reason") == "content_filter":
                    refusal = message.get("refusal", "Content filter triggered")
                    logger.warning(f"OpenAI refusal: {refusal}")
                    raise ValueError(f"OpenAI content filter refusal: {refusal}")

                content = message.get("content")
                if not content:
                    raise ValueError("OpenAI returned empty content")

                result = json.loads(content)

                # Log usage for cost tracking
                usage = data.get("usage", {})
                _record_api_call("openai", model, usage)
                usage_dict = _compute_usage_dict("openai", usage)

                required = [
                    "text_conflict",
                    "conflict_note",
                    "rag_result",
                    "resolution",
                    "confidence",
                    "score_adjustment",
                ]
                for field in required:
                    if field not in result:
                        raise ValueError(f"Missing field in LLM response: {field}")

                return result, usage_dict

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                retry_after = e.response.headers.get("Retry-After")
                delay = (
                    float(retry_after) if retry_after else _BASE_DELAY * (2**attempt)
                )
                await asyncio.sleep(delay)
                continue
            if e.response.status_code >= 500 and attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise
        except (httpx.ConnectTimeout, httpx.ConnectError):
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise
        except httpx.ReadTimeout:
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise

    raise RuntimeError("OpenAI max retries exceeded")


# ---------------------------------------------------------------------------
# Anthropic Provider
# ---------------------------------------------------------------------------


def _build_anthropic_schema() -> dict:
    """Build the Anthropic json_schema output_config format."""
    from models import TriageConflictResult

    schema = TriageConflictResult.model_json_schema()
    schema["additionalProperties"] = False
    return {
        "format": {
            "type": "json_schema",
            "schema": schema,
        }
    }


async def call_anthropic(
    system_content: str, user_content: str, api_key: str, model: str
) -> tuple[dict, dict]:
    """Call Anthropic Messages API with structured output via SDK.

    Uses client.messages.parse() with Pydantic-based output_config.
    Handles refusals (stop_reason="refusal") and max_tokens truncation.
    """
    from anthropic import (
        AsyncAnthropic,
        APIConnectionError,
        APITimeoutError,
        RateLimitError,
        APIStatusError,
    )

    client = AsyncAnthropic(api_key=api_key)
    output_config = _build_anthropic_schema()
    max_tokens = LLM_MAX_TOKENS

    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = await client.messages.parse(
                model=model,
                max_tokens=max_tokens,
                system=[
                    {
                        "type": "text",
                        "text": system_content,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_content}],
                output_config=output_config,
            )

            if response.parsed_output is None:
                stop_reason = response.stop_reason
                if stop_reason == "refusal":
                    logger.warning("Anthropic refusal: model declined to answer")
                    raise ValueError("Anthropic refusal: model declined to answer")
                if stop_reason == "max_tokens" and attempt < _MAX_RETRIES:
                    max_tokens = max_tokens * 2
                    logger.info(
                        f"Anthropic response truncated, retrying with max_tokens={max_tokens}"
                    )
                    await asyncio.sleep(1.0)
                    continue
                raise ValueError(
                    f"Anthropic returned unparseable response (stop_reason={stop_reason})"
                )

            result = response.parsed_output.model_dump()

            # Log usage — Anthropic returns usage in response.usage
            if hasattr(response, "usage") and response.usage:
                usage_data = {
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "cached_tokens": getattr(
                        response.usage, "cache_read_input_tokens", None
                    )
                    or 0,
                }
                _record_api_call("anthropic", model, usage_data)
                usage_dict = _compute_usage_dict("anthropic", usage_data)
            else:
                _record_api_call("anthropic", model, {})
                usage_dict = {"tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}

            return result, usage_dict

        except RateLimitError as e:
            retry_after = float(
                e.response.headers.get("retry-after", _BASE_DELAY * (2**attempt))
            )
            await asyncio.sleep(retry_after)
            continue
        except (APIConnectionError, APITimeoutError):
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise
        except APIStatusError as e:
            if e.status_code >= 500 and attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise

    raise RuntimeError("Anthropic max retries exceeded")


# ---------------------------------------------------------------------------
# Together AI Provider
# ---------------------------------------------------------------------------


def _build_together_schema() -> dict:
    """Build the Together AI json_schema response_format."""
    from models import TriageConflictResult

    schema = TriageConflictResult.model_json_schema()
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "triage_conflict",
            "schema": schema,
        },
    }


def _together_supports_json_schema(model: str) -> bool:
    """Check if the model supports json_schema response_format."""
    return model in TOGETHER_JSON_SCHEMA_MODELS


async def call_together(
    system_content: str, user_content: str, api_key: str, model: str
) -> tuple[dict, dict]:
    """Call Together AI API for open-weight models.

    Uses json_schema response_format if supported by the model.
    Always embeds the schema text in the system prompt for guidance
    (Together AI's json_schema mode is best-effort, not constrained decoding).
    """
    import httpx

    timeout = httpx.Timeout(LLM_TIMEOUT, connect=10.0)
    supports_schema = _together_supports_json_schema(model)

    request_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.1,
        "max_tokens": LLM_MAX_TOKENS,
    }

    if supports_schema:
        request_body["response_format"] = _build_together_schema()

    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    "https://api.together.xyz/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=request_body,
                )
                response.raise_for_status()
                data = response.json()
                text = data["choices"][0]["message"]["content"]
                if not text:
                    raise ValueError("Together AI returned empty content")

                if text.startswith("```"):
                    text = text.split("\n", 1)[1]
                    if text.endswith("```"):
                        text = text[:-3]

                result = json.loads(text)

                # Log usage
                usage = data.get("usage", {})
                _record_api_call("together", model, usage)
                usage_dict = _compute_usage_dict("together", usage)

                required = [
                    "text_conflict",
                    "conflict_note",
                    "rag_result",
                    "resolution",
                    "confidence",
                    "score_adjustment",
                ]
                for field in required:
                    if field not in result:
                        raise ValueError(f"Missing field in LLM response: {field}")

                return result, usage_dict

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                retry_after = e.response.headers.get("Retry-After")
                delay = (
                    float(retry_after) if retry_after else _BASE_DELAY * (2**attempt)
                )
                await asyncio.sleep(delay)
                continue
            if e.response.status_code >= 500 and attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise
        except (httpx.ConnectTimeout, httpx.ConnectError):
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_DELAY * (2**attempt))
                continue
            raise
        except httpx.ReadTimeout:
            raise

    raise RuntimeError("Together AI max retries exceeded")


# ---------------------------------------------------------------------------
# Cost Tracking
# ---------------------------------------------------------------------------


def _compute_usage_dict(provider: str, usage: dict) -> dict:
    """Extract per-call token counts and cost from an API usage dict."""
    prompt_tokens = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0) or 0
    completion_tokens = (
        usage.get("completion_tokens", 0) or usage.get("output_tokens", 0) or 0
    )
    rates = _COST_RATES.get(provider, {"input": 0.0, "output": 0.0})
    cost = (prompt_tokens / 1_000_000) * rates["input"] + (
        completion_tokens / 1_000_000
    ) * rates["output"]
    return {
        "tokens_in": prompt_tokens,
        "tokens_out": completion_tokens,
        "cost_usd": round(cost, 6),
    }


def _record_api_call(provider: str, model: str, usage: dict):
    """Record API call metrics for cost tracking."""
    prompt_tokens = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0) or 0
    completion_tokens = (
        usage.get("completion_tokens", 0) or usage.get("output_tokens", 0) or 0
    )
    cached_tokens = usage.get("cached_tokens", 0) or 0

    rates = _COST_RATES.get(provider, {"input": 0.0, "output": 0.0})
    cost = (prompt_tokens / 1_000_000) * rates["input"] + (
        completion_tokens / 1_000_000
    ) * rates["output"]

    with _cost_lock:
        _cost_tracking["total_calls"] += 1
        _cost_tracking["total_input_tokens"] += prompt_tokens
        _cost_tracking["total_output_tokens"] += completion_tokens
        _cost_tracking["total_cached_tokens"] += cached_tokens
        _cost_tracking["estimated_cost_usd"] += cost

    logger.info(
        "LLM call %s/%s: %d in, %d out, $%.4f total",
        provider,
        model,
        prompt_tokens,
        completion_tokens,
        _cost_tracking["estimated_cost_usd"],
        extra={
            "event": "llm_call",
            "duration_ms": 0,
            "provider": provider,
            "model": model,
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens,
            "cached_tokens": cached_tokens,
            "estimated_cost_usd": round(cost, 6),
            "total_cost_usd": round(_cost_tracking["estimated_cost_usd"], 4),
        },
    )


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


def _neutral_default(cve_id: str, error_msg: str) -> dict:
    """Return a neutral assessment when no provider or cache is available."""
    return {
        "text_conflict": False,
        "conflict_note": f"Cloud LLM unavailable ({error_msg[:200]}). No cached resolution available.",
        "rag_result": "NOT_QUERIED",
        "resolution": "Unable to perform semantic analysis. Deferring to Tier 1 score.",
        "confidence": 0.30,
        "score_adjustment": 0,
    }


async def evaluate_tier_2(
    cve_id: str,
    hostname: str,
    cvss_score: float,
    description: str,
    rag_context: str,
    cisa_kev: bool,
    epss_score: float,
    cvss_vector: str,
    upstream_scores: dict,
    mission_tags: dict,
    cwe_result: dict | None = None,
) -> dict:
    """
    Evaluate a vulnerability using a cloud-hosted language model.

    When AGENT_ENABLED is True, uses the AgenticEvaluator with multi-step
    tool-calling loop. Falls back to single-shot if the agent fails.

    When AGENT_ENABLED is False (default), uses the existing single-shot path.
    Falls back through: primary provider → backup provider → KNOWN_CONFLICTS → neutral default.
    Each provider uses its own retry-with-backoff logic internally.
    """

    # ── Agentic path (Sprint 20) ──────────────────────────────────────
    if AGENT_ENABLED:
        try:
            from .agent import AgenticEvaluator

            agent = AgenticEvaluator(
                max_steps=AGENT_MAX_STEPS,
                cost_budget_usd=AGENT_COST_BUDGET,
            )
            # hostname is passed directly from the ingest caller, not derived from rag_context
            result = await agent.evaluate(
                cve_id=cve_id,
                hostname=hostname,
                description=description,
                cvss_score=cvss_score,
            )
            # If the agent returned a neutral default with _fallback marker,
            # fall through to single-shot
            if result.get("_fallback") is True:
                logger.info("Agent elected fallback for %s, using single-shot", cve_id)
            else:
                logger.info(
                    "Tier 2 resolved by agent for %s in %d steps",
                    cve_id,
                    result.get("_agent", {}).get("steps", 0),
                )
                return result
        except Exception as e:
            logger.warning(
                "Agent evaluation failed for %s: %s — falling back to single-shot",
                cve_id,
                str(e)[:200],
            )

    # ── Single-shot path (original logic) ─────────────────────────────
    system_content, user_content = build_prompt(
        cve_id,
        cvss_score,
        description,
        rag_context,
        cisa_kev,
        epss_score,
        cvss_vector,
        upstream_scores,
        mission_tags,
        cwe_result=cwe_result,
    )

    # Build provider order
    providers = [(LLM_PROVIDER, LLM_API_KEY, LLM_MODEL)]
    if BACKUP_PROVIDER and BACKUP_API_KEY:
        providers.append((BACKUP_PROVIDER, BACKUP_API_KEY, BACKUP_MODEL or LLM_MODEL))

    _ZERO_USAGE = {"tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}

    last_error = None
    for provider, api_key, model in providers:
        try:
            if provider == "openai":
                result, usage = await call_openai(
                    system_content, user_content, api_key, model
                )
            elif provider == "anthropic":
                result, usage = await call_anthropic(
                    system_content, user_content, api_key, model
                )
            elif provider == "together":
                result, usage = await call_together(
                    system_content, user_content, api_key, model
                )
            else:
                raise ValueError(f"Unknown LLM provider: {provider}")

            result["_usage"] = usage
            logger.info(f"Tier 2 resolved by {provider} ({model}) for {cve_id}")
            return result

        except Exception as e:
            last_error = e
            logger.warning(
                f"Tier 2 provider {provider} ({model}) failed for {cve_id}: {str(e)[:200]}"
            )
            continue

    # Fallback: use known conflict resolutions
    if cve_id in KNOWN_CONFLICTS:
        result = dict(KNOWN_CONFLICTS[cve_id])
        result["_usage"] = dict(_ZERO_USAGE)
        result["conflict_note"] += (
            f" [Note: Cloud LLM unavailable"
            f" ({str(last_error)[:100] if last_error else 'all providers failed'})."
            f" Using cached resolution.]"
        )
        logger.warning(f"Tier 2 using KNOWN_CONFLICTS fallback for {cve_id}")
        return result

    # Neutral default for unknown CVEs
    error_msg = str(last_error)[:200] if last_error else "All providers unavailable"
    logger.error(f"Tier 2 no resolution available for {cve_id}: {error_msg}")
    neutral = _neutral_default(cve_id, error_msg)
    neutral["_usage"] = dict(_ZERO_USAGE)
    return neutral
