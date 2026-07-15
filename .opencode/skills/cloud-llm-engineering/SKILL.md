---
name: cloud-llm-engineering
description: Tier 2 cloud LLM integration, API call architecture, prompt engineering, retry/backoff, multi-provider failover. Use when editing pipeline/tier_2.py, or working on LLM-related pipeline logic.
---

# TriageMate Cloud LLM Engineering

## GitHub Workflow

Use the current assigned task workspace; never create or switch worktrees. Report the workspace path, branch, SHA, and verification evidence to the Commander; `git-steward` owns Git/GitHub lifecycle actions.

## Providers
Primary → Backup → KNOWN_CONFLICTS fallback → neutral default
- OpenAI (gpt-4o-mini)
- Anthropic (Claude)
- Together AI

## Retry Strategy
- 3 attempts with 2^N-second exponential backoff
- Provider failover if primary fails
- `KNOWN_CONFLICTS` dictionary as zero-cost fallback for demo CVEs
- Pipeline MUST degrade gracefully — never crash

## Force-Reflection Prompt Template
Step A → Step B → Step C → structured JSON output

## Key Files
- `backend/pipeline/tier_2.py` — cloud LLM call, force-reflection prompt, fallback chain, provider abstraction, retry logic
- `backend/integrations/nvd.py` — NVD API lookups (used alongside LLM for CWE context)

## Cost Targets
~$0.0004 per analysis with gpt-4o-mini (with KNOWN_CONFLICTS caching most)

## Requirements
- API keys from environment variables — never hardcode
- Every LLM call logs `{"event":"llm_call"}` with token counts
- `KNOWN_CONFLICTS` dict must stay in sync with demo scenario changes
- Graceful degradation: retry → backup provider → known conflicts → neutral default
