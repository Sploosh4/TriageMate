# TriageMate Book — Chapter 7: Tier 2 — The Cloud LLM Layer

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

So we have reached the end of the automated pipeline. Tier 0 ran its deterministic rules in milliseconds. Tier 1 pushed the vulnerability through eight hundred XGBoost decision trees and came back with an exploitation probability. For most vulnerabilities, that is enough. The scoring engine takes those signals, computes a priority score, and sends the case to the queue. Done. The analyst never thinks about it again.

But some vulnerabilities are uncertain. The deterministic rules say "maybe." The ML model says "not sure" — its ensemble variance is above 0.15, its confidence is below 0.3, or the boundary between two risk bands is too close to call. For these cases, the pipeline does something different. It escalates to Tier 2.

Tier 2 is the final automated analysis stage before human review. It is a cloud-hosted large language model — OpenAI, Anthropic, or Together AI, depending on configuration — and it is asked to perform a structured, adversarial analysis of the vulnerability. The key word there is structured. This is not a free-form chat where the LLM can waffle. The prompt forces it through a three-step reasoning process designed to surface tension between the exploitability signals and the mitigating factors. We call it force-reflection.

The file is `backend/pipeline/tier_2.py`, weighing in at 724 lines. Let us open it up.

---

## The Force-Reflection Prompt Template

The core innovation in Tier 2 is not the choice of LLM provider or the API call pattern. It is the prompt. Most vulnerability triage tools that use LLMs ask a simple question: "Is this vulnerability critical? Rate it from 1 to 10." The LLM answers immediately, and that answer is often wrong. LLMs are pattern matchers. They see a CVSS of 9.8 and a KEV tag and jump to "this is critical" without considering whether the affected asset is even running the vulnerable service, or whether a mitigation has been applied, or whether the attack requires privileges that the adversary does not have.

The force-reflection prompt prevents that. It breaks the analysis into three mandatory steps:

**Step A — Primary Exploitability Assessment.** The LLM must analyse the CVSS vector, the EPSS score, the CISA KEV status, and the CWE classification to assess whether this vulnerability presents a credible, exploitable threat to this specific asset. This is the knee-jerk pass. The LLM gets to say what it thinks at first glance.

**Step B — Counter-Argument.** Now the LLM must actively argue against its own first impression. It must consider mitigating factors. The asset context from Pre-Tier mission classification. The RAG documentation retrieved from LanceDB — internal configuration records, CMDB entries, change history. The upstream Tier 1 scores. It must identify any negative constraints that could nullify or reduce exploitability: non-default settings required, mitigations already in place, attack surface not reachable, user interaction requirements, privilege prerequisites.

**Step C — Final Determination.** Synthesise A and B. Weigh the primary assessment against the counter-argument. Decide whether a text conflict exists — where the exploitability signal and the mitigating constraint are in genuine tension that cannot be resolved without human investigation. Then output a structured JSON object with the determination.

This three-step pattern forces the LLM to challenge its own conclusions. It is the difference between asking "what do you think?" and asking "make a case, then argue against it, then tell me where the tension is." The result is a more balanced, more defensible assessment.

The system prompt is static. It never changes between calls. This is by design. Anthropic supports `cache_control: {"type": "ephemeral"}` on system messages, which means the provider caches the system prompt prefix across calls with the same prompt text. For recurring analyses — same hostname, same CWE patterns — the cache hit rate is high. The cost savings are substantial: 50 to 90 percent reduction on cached prefix tokens, depending on the workload.

---

## The Response Schema

The LLM does not produce free text. It produces a structured JSON object conforming to the `TriageConflictResult` Pydantic model in `backend/models.py:112`. Every field is required — no optional fields, no unions. This is a deliberate constraint to maintain compatibility with Anthropic's JSON Schema subset, which does not support `anyOf` or `oneOf`.

```json
{
  "text_conflict": true,
  "conflict_note": "Plain-English explanation (max 300 chars)",
  "rag_result": "UNCERTAIN|CONFIRMED|NOT_NEEDED",
  "resolution": "Resolution recommendation (max 500 chars)",
  "confidence": 0.0-1.0,
  "score_adjustment": -70 to +10
}
```

Let me walk through each field.

**`text_conflict`** is a boolean. True means the LLM found contradictory evidence — the exploitability signals and the mitigating constraints are in tension. False means the signals are aligned.

**`conflict_note`** is a plain-English explanation of the conflict, capped at 300 characters. This gets surfaced to the analyst in the case detail view. It is the human-readable summary of why the LLM is unsure.

**`rag_result`** captures whether the RAG search resolved the conflict. `UNCERTAIN` means the RAG documentation was ambiguous or contradictory. `CONFIRMED` means the RAG documentation provided definitive evidence one way or the other. `NOT_NEEDED` means there was no conflict to resolve.

**`resolution`** is the recommended action, up to 500 characters. This is the LLM's best judgement for what the analyst should do: assign a particular score band, flag for manual verification, escalate to a specific team.

**`confidence`** is the LLM's self-assessed confidence in its resolution, from 0.0 to 1.0. This is not a calibrated probability — LLMs are notoriously bad at self-calibration — but it is a useful signal for the scoring engine. A confidence of 0.91 carries more weight than 0.30.

**`score_adjustment`** is the most important field. It is an integer from -70 to +10 that modifies the priority score computed by the scoring engine. The range is asymmetric by design. A **negative** adjustment means "this vulnerability is less critical than the raw numbers suggest" — the priority score goes down. A **positive** adjustment means "this is worse than it looks" — the priority score goes up, but only by a maximum of +10. The asymmetry reflects the system's philosophy: the deterministic and ML tiers are conservative and tend to over-prioritise. The LLM's main job is to catch false positives — vulnerabilities that look bad on paper but are mitigated in practice. It can dramatically de-prioritise a vulnerability (down to -70), but it can only slightly raise urgency (up to +10) because the upstream tiers already handle the "this is definitely critical" cases. Raising urgency is rare.

All three known conflict examples in the codebase use negative adjustments:
- CVE-2023-36884: score_adjustment -15 (RCE is real but mitigated by Windows 10+ protections)
- CVE-2023-22515: score_adjustment -37 (Confluence access control bypass, but not a core system)
- CVE-2022-47966: score_adjustment -66 (ManageEngine SAML RCE, but SAML is disabled)

Each one is the LLM saying "the numbers say this is urgent, but here is why it is not."

---

## Provider Chain

Tier 2 does not depend on a single provider. It has a fallback chain with four layers.

**Primary provider.** Configured via `TRIAGEMATE_LLM_PROVIDER` environment variable. Default is `openai`. The model defaults to `gpt-4o-mini`, chosen for the best cost-to-quality ratio at MVP scale. The API key must start with `sk-` or `sk-proj-` for OpenAI, or `sk-ant-api03-` for Anthropic. If the key format does not match, a warning is logged at import time but the system does not block — the key might still work if the provider changed its format.

**Backup provider.** Configured via `TRIAGEMATE_LLM_BACKUP_PROVIDER`. Optional. If the primary provider fails (rate limited, timeout, server error), the pipeline tries the backup. The backup can be a different provider entirely — for example, primary OpenAI with backup Anthropic, or vice versa. The backup model defaults to the primary model name if `TRIAGEMATE_LLM_BACKUP_MODEL` is not set.

**Tertiary fallback — KNOWN_CONFLICTS.** If both cloud providers fail, Tier 2 checks a hardcoded dictionary of known conflict resolutions in `tier_2.py:54`. This currently contains three entries:
- `CVE-2023-36884` — Microsoft Office/Windows Search RCE on `communities.wa.gov.au`. Confidence 0.72, score_adjustment -15.
- `CVE-2023-22515` — Atlassian Confluence Broken Access Control on `police.wa.gov.au`. Confidence 0.68, score_adjustment -37.
- `CVE-2022-47966` — ManageEngine SAML RCE on `finance.wa.gov.au`. Confidence 0.91, score_adjustment -66.

Each entry is a complete `TriageConflictResult` object. When triggered, the `conflict_note` is appended with a note that the cloud LLM was unavailable and the cached resolution was used. This ensures the analyst knows the assessment was not generated fresh.

**Neutral default.** If nothing works — no providers configured, no KNOWN_CONFLICTS match — Tier 2 returns a neutral assessment: `text_conflict: false`, `confidence: 0.30`, `score_adjustment: 0`. The vulnerability proceeds to the scoring engine with no LLM override. This is the safe default: do nothing rather than introduce spurious adjustments.

---

## Retry Logic

Each provider call has its own retry loop with exponential backoff. The pattern is identical across OpenAI, Anthropic, and Together:

- Maximum 3 retries (`_MAX_RETRIES = 3`)
- Base delay of 1 second (`_BASE_DELAY = 1.0`)
- Backoff formula: `_BASE_DELAY * (2^attempt)` — so 1s, 2s, 4s
- Total worst-case wait: 7 seconds per provider

Retries are triggered on:
- HTTP 429 (rate limited) — respects `Retry-After` header if present
- HTTP 5xx (server errors)
- Connection timeouts (`httpx.ConnectTimeout`, `httpx.ConnectError`)
- Read timeouts (`httpx.ReadTimeout`) — these are not retried because the server may be processing slowly

If the provider is exhausted, the pipeline moves to the next provider in the chain. A single failure does not block the entire Tier 2 analysis.

---

## RAG Context Injection

Before the LLM call, the pipeline queries a LanceDB vector store for internal documentation about the affected asset. This is the Retrieval-Augmented Generation step — RAG.

The query is constructed from the hostname and CWE class. The vector store uses `all-MiniLM-L6-v2` embeddings (384 dimensions) to find semantically similar documents. If the vector search returns no results, a fallback full-text search is attempted. Up to three documents are returned, concatenated into a single `rag_context` string capped at 5000 characters (approximately 2000 tokens).

The RAG context is injected into the prompt under Step B — Counter-Argument. The LLM is told to consider this context when looking for mitigating factors. The idea is that the LLM should not just reason in abstract — it should reason with the actual configuration records, change history, and documentation for this specific asset.

The RAG result has a 60-second TTL cache keyed by `{hostname}::{cwe_class}::{top_k}`. If the same asset is hit with concurrent ingest of different CVEs in the same CWE class, the LanceDB query runs once and the cache serves subsequent calls. This is important during scanner floods where a single hostname might have dozens of open vulnerabilities.

---

## Cost Economics

Each Tier 2 analysis is cheap by design. With OpenAI `gpt-4o-mini` at default settings:
- Input: approximately 500 tokens (system prompt + CVE description + CVSS vector + RAG context + upstream scores)
- Output: approximately 200 tokens (the structured JSON response)
- Cost per call: approximately $0.0004

At that rate, processing 2500 uncertain vulnerabilities costs about one dollar.

The cost tracking accumulators in `tier_2.py:106-120` maintain running totals:
- `total_calls` — number of LLM API calls
- `total_input_tokens` — aggregate input tokens
- `total_output_tokens` — aggregate output tokens
- `total_cached_tokens` — aggregate cached prefix tokens (Anthropic only)
- `estimated_cost_usd` — running total estimated cost

The rates table is approximate and model-specific:
- OpenAI: $0.15/M input, $0.60/M output
- Anthropic: $0.25/M input, $1.25/M output
- Together: $0.20/M input, $0.20/M output

These are used for estimation, not billing. The actual cost depends on the specific model version and provider pricing at the time of use.

---

## Provider Implementation Details

### OpenAI

Uses `httpx.AsyncClient` to call the Chat Completions API directly — no OpenAI SDK dependency. The `response_format` is set to `json_schema` with strict schema enforcement. This is a relatively new API feature that guarantees the response matches the schema. If the schema violation rate is high, the API returns an error rather than malformed JSON.

The schema is built dynamically from the `TriageConflictResult` Pydantic model with `additionalProperties: false` and `strict: true`. The temperature is set to 0.1 to reduce variability — we want deterministic, repeatable assessments.

Content filtering is handled explicitly. If the `finish_reason` is `content_filter`, the response is discarded and treated as a refusal.

### Anthropic

Uses the official `AsyncAnthropic` SDK for structured output. The SDK provides `client.messages.parse()` which returns Pydantic-model-parsed output directly via `output_config`. This is cleaner than manual JSON parsing.

The key Anthropic-specific feature is `cache_control` on the system message. The system content is wrapped with `cache_control: {"type": "ephemeral"}`. When the same system prompt is sent repeatedly, Anthropic caches the prefix and returns a reduced token cost. The cached token count is logged in the cost tracking accumulators.

If the response is truncated (`stop_reason: "max_tokens"`), the pipeline doubles `max_tokens` and retries once. If the model refuses (`stop_reason: "refusal"`), the response is discarded.

### Together AI

Supports both JSON schema and plain JSON mode. The `TOGETHER_JSON_SCHEMA_MODELS` frozenset in `tier_2.py:45-51` lists models confirmed to support `json_schema` `response_format`:
- `meta-llama/Llama-3.3-70B-Instruct-Turbo`
- `Qwen/Qwen3.5-9B`
- `Qwen/Qwen3.5-32B`

For models not in this list, the schema is still embedded in the system prompt text as guidance, but no structured `response_format` is set. The response is parsed from raw JSON, stripping markdown code fences if present (Together models sometimes wrap JSON in triple backticks).

---

## API Key Authentication

Each provider validates API key format at import time:
- OpenAI keys must start with `sk-` or `sk-proj-`
- Anthropic keys must start with `sk-ant-api03-`

If no valid key is configured for a provider, that provider is skipped with a logged warning. The pipeline moves to the next provider in the fallback chain. This means you can configure only an Anthropic backup and no OpenAI primary, and the system handles it gracefully — it skips OpenAI silently and tries Anthropic.

---

## Training the Analyst: The Demo Rows

The KNOWN_CONFLICTS dictionary serves a dual purpose. It is a runtime fallback when the API is unavailable, but it is also a training tool. Each entry is a realistic example of the kind of text conflict the LLM is supposed to find.

Let us walk through them as case studies.

**CVE-2023-36884 — Office/Windows Search RCE.** This is an actively exploited vulnerability used in spear-phishing campaigns targeting government social services. The CVSS is high, KEV is confirmed, exploit code is weaponised. But there is a catch: Microsoft released a registry key mitigation that blocks the attack vector. The RAG search returns conflicting GPO deployment records — the ASR rule may or may not be active on this endpoint. The LLM cannot resolve this definitively. It flags the conflict, assigns confidence 0.72, and adjusts the score down by 15 points. The resolution: "Exploitability signal dominates. Mitigation status unverifiable. Assign score 63 — Critical band. Flag for manual ASR verification."

**CVE-2023-22515 — Confluence Broken Access Control.** CVSS 10.0. CISA KEV. Actively exploited by nation-state groups targeting law enforcement Confluence instances. But the change record says the system was upgraded to 8.5.2, while the scanner still fingerprints 8.5.1. The RAG search reveals hostname alias confusion between the production server and a staging server. The LLM assigns confidence 0.68, score adjustment -37. The resolution: "Scanner evidence carries more weight than change record. Assign score 41 — Medium band. ICT team demonstrated awareness within 14 days, reducing urgency."

**CVE-2022-47966 — ManageEngine SAML RCE.** CVSS 9.8. Pre-auth RCE. Multiple public PoCs. CISA KEV. Exploited by APT groups. The Tier 0 rules did not auto-resolve because ManageEngine spans 24 products with varying SAML profiles. But the RAG search confirms SAML SSO is explicitly disabled on this instance — `saml.sso.enabled=false`, LDAP-only authentication, `/SamlResponseServlet` returns 404. The LLM is highly confident (0.91) and adjusts the score down by 66 points. The resolution: "SAML-disabled configuration eliminates attack surface. Assign score 22 — Low band. Persistent flag to alert if SAML is ever enabled. Recommend patching to remove vulnerable libraries."

Each of these illustrates why Tier 2 exists. A deterministic rule engine cannot reason about SAML configuration nuances. An XGBoost model cannot read change records and detect hostname alias confusion. But an LLM, prompted with the right context and forced to argue both sides, can.

---

## What Is Planned

Tier 2 is functionally complete for MVP. The provider chain works, the force-reflection prompt is delivering balanced assessments, the cost tracking is in place, and the fallback chain covers every failure mode we have tested.

There is one post-MVP item on the roadmap: replacing the cloud LLM with a local model for air-gapped deployments. The candidate is a ModernBERT-based CWE encoder fine-tuned for vulnerability classification. This would remove the dependency on external API calls, making Tier 2 usable in classified or disconnected environments. But the current implementation — cloud-first with graceful fallback — is the right choice for MVP. Cloud LLMs are cheaper to integrate, easier to swap, and orders of magnitude more capable than anything we could run locally today.

The force-reflection pattern, however, stays. Whether the model runs in San Francisco or on a server in a SOC basement, the three-step adversarial reasoning prompt is the architecture. That is the innovation. The provider is just the engine.
