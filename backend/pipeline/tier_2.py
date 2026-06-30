"""
Tier 2: Semantic Analysis via Cloud-Hosted Language Model.

This stage receives cases that Tier 0 and Tier 1 could not confidently resolve.
It sends the CVE description, upstream scores, and asset context to a cloud LLM
API that runs the adversarial force-reflection loop. The API returns a structured
JSON response with the conflict assessment and final resolution.

Supported providers (configured via environment variable):
- OpenAI (gpt-4o-mini recommended for MVP cost optimization)
- Anthropic (claude-3-haiku recommended for MVP cost optimization)
- Together AI (hosted open-weight models)
"""

import os
import json
import httpx
from typing import Optional

# Provider configuration from environment
LLM_PROVIDER = os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai")
LLM_API_KEY = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
LLM_MODEL = os.getenv("TRIAGEMATE_LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = int(os.getenv("TRIAGEMATE_LLM_TIMEOUT", "30"))

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
        "rag_result": "UNCERTAIN — CMDB records conflict",
        "resolution": "Exploitability signal dominates. Mitigation status unverifiable. "
                      "Assign score 63 — Critical band. Flag for manual ASR verification.",
        "confidence": 0.72,
        "score_adjustment": -15
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
        "rag_result": "UNCERTAIN — hostname alias confusion",
        "resolution": "Scanner evidence carries more weight than change record. "
                      "Assign score 41 — Medium band. ICT team demonstrated awareness "
                      "within 14 days, reducing urgency.",
        "confidence": 0.68,
        "score_adjustment": -37
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
        "rag_result": "CONFIRMED — SAML disabled since 2021 deployment",
        "resolution": "SAML-disabled configuration eliminates attack surface. "
                      "Assign score 22 — Low band. Persistent flag to alert if "
                      "SAML is ever enabled. Recommend patching to remove vulnerable libraries.",
        "confidence": 0.91,
        "score_adjustment": -66
    }
}


def build_prompt(cve_id: str, cvss_score: float, description: str,
                 config_context: dict, upstream_scores: dict,
                 mission_tags: dict) -> str:
    """Build the force-reflection prompt for the cloud LLM."""

    return f"""You are a vulnerability prioritization analyst for the Western Australian 
government. Analyze this vulnerability and determine whether a text conflict exists 
between the exploitability signals and any mitigating constraints.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {description}

Asset Context:
- Mission Prevalence: {mission_tags.get('mission_prevalence', 'Unknown')}
- Public Well-Being Impact: {mission_tags.get('public_wellbeing_impact', 'Unknown')}
- Configuration: {json.dumps(config_context, indent=2)}

Upstream Tier 1 Scores:
- Exploitation Probability: {upstream_scores.get('exploitation_probability', 'N/A')}
- Model Confidence: {upstream_scores.get('confidence', 'N/A')}

Perform the following analysis:

Step A — Primary Exploitability Assessment:
Based on the CVE description, CVSS score, threat intelligence feeds (CISA KEV status 
is implicitly reflected in the upstream scores), and the asset context, assess whether 
this vulnerability presents a credible, exploitable threat to this specific asset.

Step B — Counter-Argument:
Identify any negative constraints in the vulnerability advisory or asset configuration 
that could nullify or reduce the exploitability. Consider: non-default settings required, 
mitigation already in place, attack surface not reachable, user interaction requirements, 
privilege prerequisites.

Step C — Final Determination:
Weigh the primary assessment against the counter-argument. Determine whether a text 
conflict exists (where the exploitability signal and the mitigating constraint are in 
tension and cannot be definitively resolved without human investigation).

Return your analysis as a JSON object with exactly these fields:
{{
  "text_conflict": true or false,
  "conflict_note": "Plain-English explanation of the conflict, if any. Max 300 characters.",
  "rag_result": "UNCERTAIN if documentation is ambiguous, CONFIRMED if configuration is verified, NOT_NEEDED if no conflict exists.",
  "resolution": "Plain-English resolution recommendation. Max 500 characters.",
  "confidence": float between 0.0 and 1.0 indicating your certainty in this resolution,
  "score_adjustment": integer between -70 and +10 representing how many points to add or subtract from the current priority score
}}

Reply with ONLY the JSON object. No preamble, no explanation, no markdown fences."""


async def call_openai(prompt: str) -> dict:
    """Call OpenAI chat completions API."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500,
                "response_format": {"type": "json_object"}
            }
        )
        response.raise_for_status()
        data = response.json()
        return json.loads(data["choices"][0]["message"]["content"])


async def call_anthropic(prompt: str) -> dict:
    """Call Anthropic Messages API."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": LLM_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "max_tokens": 500,
                "temperature": 0.1,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        response.raise_for_status()
        data = response.json()
        text = data["content"][0]["text"]
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)


async def call_together(prompt: str) -> dict:
    """Call Together AI API for open-weight models."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        response = await client.post(
            "https://api.together.xyz/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500
            }
        )
        response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)


async def evaluate_tier_2(cve_id: str, cvss_score: float, description: str,
                          config_context: dict, upstream_scores: dict,
                          mission_tags: dict) -> dict:
    """
    Evaluate a vulnerability using a cloud-hosted language model.
    Falls back to known conflict resolutions if the API is unavailable
    or returns an unparseable response.
    """

    prompt = build_prompt(cve_id, cvss_score, description, config_context,
                          upstream_scores, mission_tags)

    try:
        if LLM_PROVIDER == "openai":
            result = await call_openai(prompt)
        elif LLM_PROVIDER == "anthropic":
            result = await call_anthropic(prompt)
        elif LLM_PROVIDER == "together":
            result = await call_together(prompt)
        else:
            raise ValueError(f"Unknown LLM provider: {LLM_PROVIDER}")

        required = ["text_conflict", "conflict_note", "rag_result",
                    "resolution", "confidence", "score_adjustment"]
        for field in required:
            if field not in result:
                raise ValueError(f"Missing field in LLM response: {field}")

        return result

    except Exception as e:
        if cve_id in KNOWN_CONFLICTS:
            result = dict(KNOWN_CONFLICTS[cve_id])
            result["conflict_note"] += f" [Note: Cloud LLM unavailable ({str(e)[:100]}). Using cached resolution.]"
            return result

        return {
            "text_conflict": False,
            "conflict_note": f"Cloud LLM unavailable ({str(e)[:100]}). No cached resolution available.",
            "rag_result": "NOT_QUERIED",
            "resolution": "Unable to perform semantic analysis. Deferring to Tier 1 score.",
            "confidence": 0.30,
            "score_adjustment": 0
        }
