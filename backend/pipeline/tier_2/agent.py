"""
AgenticEvaluator — multi-step CVE investigation agent for Tier 2.

The agent receives a minimal prompt (cve_id, hostname, description, cvss_score)
and iteratively calls tools to gather intelligence before submitting a final
resolution. Supports OpenAI (function calling), Anthropic (tool_use), and
Together AI (JSON-mode with tool guidance).
"""

import json
import os
import logging
from dotenv import load_dotenv
from pathlib import Path
from pipeline.tier_2.tools import TOOL_DEFINITIONS, execute_tool

_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

logger = logging.getLogger("triagemate.tier_2.agent")

# ── Constants ─────────────────────────────────────────────────────────────

_FINAL_RESOLUTION_SCHEMA = {
    "type": "object",
    "properties": {
        "text_conflict": {"type": "boolean"},
        "conflict_note": {"type": "string"},
        "rag_result": {
            "type": "string",
            "enum": ["UNCERTAIN", "CONFIRMED", "NOT_NEEDED"],
        },
        "resolution": {"type": "string"},
        "confidence": {"type": "number"},
        "score_adjustment": {"type": "integer"},
    },
    "required": [
        "text_conflict",
        "conflict_note",
        "rag_result",
        "resolution",
        "confidence",
        "score_adjustment",
    ],
}

_NEUTRAL_DEFAULT = {
    "text_conflict": False,
    "conflict_note": "Agent evaluation terminated without reaching a conclusion. Using neutral default.",
    "rag_result": "UNCERTAIN",
    "resolution": "Unable to complete agentic investigation. Deferring to upstream scores.",
    "confidence": 0.30,
    "score_adjustment": 0,
}

_COST_RATES = {
    "openai": {"input": 0.15, "output": 0.60},
    "anthropic": {"input": 0.25, "output": 1.25},
    "together": {"input": 0.20, "output": 0.20},
}

_MAX_TOOL_FAILURES = 3

# ── Provider Configuration ────────────────────────────────────────────────

LLM_PROVIDER = os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai")
LLM_API_KEY = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
LLM_MODEL = os.getenv("TRIAGEMATE_LLM_MODEL", "gpt-4o-mini")
LLM_MAX_TOKENS = int(os.getenv("TRIAGEMATE_LLM_MAX_TOKENS", "2048"))
LLM_TIMEOUT = int(os.getenv("TRIAGEMATE_LLM_TIMEOUT", "30"))
LLM_BASE_URL = os.getenv("TRIAGEMATE_LLM_BASE_URL", "https://api.openai.com/v1")


# ── System Prompt Template ────────────────────────────────────────────────

_SYSTEM_PROMPT_TEMPLATE = """You are a vulnerability prioritization analyst for the Western Australian government.

You have access to the following tools to investigate CVEs:

{tool_descriptions}

Your task: Investigate the given CVE by calling tools iteratively to gather intelligence.
After sufficient investigation, submit a final resolution in JSON format.

Investigation strategy:
1. Start by checking KEV status, EPSS score, and NVD data
2. Look up CWE classification and MITRE ATT&CK techniques
3. Query asset context from CMDB and network context
4. Check for public exploits (ExploitDB, Metasploit)
5. Query telemetry and advisories
6. Use RAG for any additional context

When you have enough information, submit your resolution as a JSON object with these fields:
- text_conflict (bool): whether there is a conflict between exploitability signals and mitigations
- conflict_note (str): plain-English explanation of the conflict (max 300 chars)
- rag_result (str): "UNCERTAIN", "CONFIRMED", or "NOT_NEEDED"
- resolution (str): resolution recommendation (max 500 chars)
- confidence (float): 0.0 to 1.0
- score_adjustment (int): -20 to +20

IMPORTANT: You must call at least 2-3 tools before submitting a resolution.
Do NOT submit a resolution without investigating first.
"""


# ── AgenticEvaluator ──────────────────────────────────────────────────────


class AgenticEvaluator:
    """Multi-step agentic evaluator for Tier 2 CVE analysis.

    The LLM receives tool definitions and can call them iteratively
    to investigate a CVE before submitting a final resolution.
    """

    def __init__(
        self,
        max_steps: int = 15,
        cost_budget_usd: float = 0.50,
        agent_enabled: bool = True,
    ):
        self.max_steps = max_steps
        self.cost_budget_usd = cost_budget_usd
        self.agent_enabled = agent_enabled
        self._step_count = 0
        self._consecutive_tool_failures = 0
        self._cost_so_far = 0.0
        self._tokens_in = 0
        self._tokens_out = 0
        self._provider = LLM_PROVIDER

    # ── Public API ────────────────────────────────────────────────────────

    async def evaluate(
        self,
        cve_id: str,
        hostname: str,
        description: str,
        cvss_score: float,
    ) -> dict:
        """Multi-step investigation loop.

        Args:
            cve_id: The CVE identifier (e.g. CVE-2023-36884)
            hostname: The asset hostname
            description: CVE description text
            cvss_score: CVSS base score

        Returns:
            dict matching TriageConflictResult schema, plus _usage and _agent metadata
        """
        # Reset state for this evaluation
        self._reset()

        provider = self._provider
        api_key = LLM_API_KEY
        model = LLM_MODEL

        if not api_key:
            logger.warning(
                "No LLM API key configured for agent, returning neutral default"
            )
            return self._make_neutral_default("No LLM API key configured")

        # Build system prompt with tool descriptions
        tool_descriptions = self._format_tool_descriptions()
        system_content = _SYSTEM_PROMPT_TEMPLATE.format(
            tool_descriptions=tool_descriptions
        )

        # Initial user prompt with minimal context
        user_content = (
            f"Investigate CVE: {cve_id}\n"
            f"Hostname: {hostname}\n"
            f"CVSS Score: {cvss_score}\n"
            f"Description: {description}\n\n"
            "Call tools to investigate this vulnerability. "
            "When you have enough information, submit your final resolution as JSON."
        )

        conversation = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]

        while self._step_count < self.max_steps:
            self._step_count += 1
            logger.info(
                "Agent step %d/%d for %s",
                self._step_count,
                self.max_steps,
                cve_id,
                extra={
                    "event": "agent_step",
                    "step": self._step_count,
                    "max_steps": self.max_steps,
                    "cve_id": cve_id,
                    "cost_so_far": round(self._cost_so_far, 6),
                },
            )

            try:
                response = await self._call_llm(conversation, provider, api_key, model)
            except Exception as e:
                logger.warning("LLM call failed at step %d: %s", self._step_count, e)
                self._record_cost(
                    provider, {"prompt_tokens": 0, "completion_tokens": 0}
                )
                continue

            # Check cost budget
            if self._cost_so_far > self.cost_budget_usd:
                logger.warning(
                    "Agent cost budget exceeded for %s: $%.4f > $%.4f",
                    cve_id,
                    self._cost_so_far,
                    self.cost_budget_usd,
                )
                result = self._make_neutral_default(
                    f"Cost budget exceeded (${self._cost_so_far:.4f} > ${self.cost_budget_usd:.4f})"
                )
                return self._attach_usage(result)

            # Parse response
            tool_calls = response.get("tool_calls", [])
            content = response.get("content", "")

            if tool_calls:
                # Execute tool calls
                for tc in tool_calls:
                    tool_name = tc.get("function", {}).get("name", "") or tc.get(
                        "name", ""
                    )
                    raw_args = tc.get("function", {}).get("arguments", "{}") or tc.get(
                        "arguments", "{}"
                    )

                    try:
                        if isinstance(raw_args, str):
                            params = json.loads(raw_args)
                        else:
                            params = raw_args
                    except json.JSONDecodeError:
                        params = {}

                    tool_result = execute_tool(tool_name, params)

                    if tool_result.get("success"):
                        self._consecutive_tool_failures = 0
                    else:
                        self._consecutive_tool_failures += 1

                    # Append assistant message with tool call
                    conversation.append(self._build_assistant_tool_call(tc))
                    # Append tool result
                    conversation.append(self._build_tool_result(tc, tool_result))

                    # Check consecutive failures
                    if self._consecutive_tool_failures >= _MAX_TOOL_FAILURES:
                        logger.warning(
                            "%d consecutive tool failures for %s",
                            _MAX_TOOL_FAILURES,
                            cve_id,
                        )
                        result = self._make_neutral_default(
                            f"{_MAX_TOOL_FAILURES} consecutive tool call failures"
                        )
                        return self._attach_usage(result)
            elif content:
                # Try to parse as final resolution JSON
                parsed = self._try_parse_resolution(content)
                if parsed is not None:
                    logger.info(
                        "Agent completed investigation for %s in %d steps",
                        cve_id,
                        self._step_count,
                    )
                    return self._attach_usage(parsed)
                else:
                    # LLM responded with text but not valid JSON — treat as intermediate
                    conversation.append({"role": "assistant", "content": content})
            else:
                # Empty response — might be a refusal
                logger.warning(
                    "Agent received empty response at step %d", self._step_count
                )
                continue

        # Step limit reached
        logger.warning("Agent step limit (%d) reached for %s", self.max_steps, cve_id)
        result = self._make_neutral_default(f"Step limit ({self.max_steps}) reached")
        return self._attach_usage(result)

    # ── LLM Call Methods ──────────────────────────────────────────────────

    async def _call_llm(
        self, conversation: list[dict], provider: str, api_key: str, model: str
    ) -> dict:
        """Call the LLM with the current conversation.

        Returns a dict with 'content' (str) and/or 'tool_calls' (list).
        """
        if provider == "openai":
            return await self._call_openai(conversation, api_key, model)
        elif provider == "anthropic":
            return await self._call_anthropic(conversation, api_key, model)
        elif provider == "together":
            return await self._call_together(conversation, api_key, model)
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

    async def _call_openai(
        self, conversation: list[dict], api_key: str, model: str
    ) -> dict:
        """Call OpenAI with function calling tools."""
        import httpx

        timeout = httpx.Timeout(LLM_TIMEOUT, connect=10.0)

        # Prepare messages (convert tool role and rename system correctly)
        messages = []
        for msg in conversation:
            role = msg["role"]
            if role == "system":
                messages.append({"role": "system", "content": msg.get("content", "")})
            elif role == "user":
                messages.append({"role": "user", "content": msg.get("content", "")})
            elif role == "assistant":
                entry = {"role": "assistant"}
                if msg.get("content"):
                    entry["content"] = msg["content"]
                if msg.get("tool_calls"):
                    entry["tool_calls"] = msg["tool_calls"]
                messages.append(entry)
            elif role == "tool":
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", ""),
                    }
                )
            elif role == "function":
                messages.append(
                    {
                        "role": "function",
                        "name": msg.get("name", ""),
                        "content": msg.get("content", ""),
                    }
                )

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{LLM_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0.1,
                    "max_tokens": LLM_MAX_TOKENS,
                    "tools": TOOL_DEFINITIONS,
                    "tool_choice": "auto",
                },
            )
            response.raise_for_status()
            data = response.json()

        choice = data["choices"][0]
        message = choice["message"]

        usage = data.get("usage", {})
        self._record_cost("openai", usage)

        result = {"content": message.get("content", "")}

        if message.get("tool_calls"):
            result["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                }
                for tc in message["tool_calls"]
            ]

        return result

    async def _call_anthropic(
        self, conversation: list[dict], api_key: str, model: str
    ) -> dict:
        """Call Anthropic with tool_use support."""
        import httpx

        timeout = httpx.Timeout(LLM_TIMEOUT, connect=10.0)

        # Extract system message
        system_text = ""
        messages_for_api = []
        for msg in conversation:
            role = msg["role"]
            if role == "system":
                system_text = msg.get("content", "")
            elif role == "user":
                content = msg.get("content", "")
                if content:
                    messages_for_api.append({"role": "user", "content": content})
            elif role == "assistant":
                content = msg.get("content", "")
                tool_calls = msg.get("tool_calls", [])
                if content or tool_calls:
                    entry = {"role": "assistant", "content": []}
                    if content:
                        entry["content"].append({"type": "text", "text": content})
                    for tc in tool_calls:
                        entry["content"].append(
                            {
                                "type": "tool_use",
                                "id": tc.get("id", ""),
                                "name": tc.get("function", {}).get("name", ""),
                                "input": json.loads(
                                    tc.get("function", {}).get("arguments", "{}")
                                ),
                            }
                        )
                    messages_for_api.append(entry)
            elif role == "tool":
                messages_for_api.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.get("tool_call_id", ""),
                                "content": msg.get("content", ""),
                            }
                        ],
                    }
                )

        # Build anthropic-style tools
        anthropic_tools = []
        for t in TOOL_DEFINITIONS:
            anthropic_tools.append(
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["parameters"],
                }
            )

        body = {
            "model": model,
            "max_tokens": LLM_MAX_TOKENS,
            "system": [{"type": "text", "text": system_text}],
            "messages": messages_for_api,
            "tools": anthropic_tools,
            "temperature": 0.1,
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            response.raise_for_status()
            data = response.json()

        usage = data.get("usage", {})
        self._record_cost("anthropic", usage)

        content_blocks = data.get("content", [])
        result = {"content": "", "tool_calls": []}

        for block in content_blocks:
            if block["type"] == "text":
                text = block.get("text", "")
                if result["content"]:
                    result["content"] += "\n" + text
                else:
                    result["content"] = text
            elif block["type"] == "tool_use":
                result["tool_calls"].append(
                    {
                        "id": block.get("id", ""),
                        "type": "function",
                        "name": block.get("name", ""),
                        "function": {
                            "name": block.get("name", ""),
                            "arguments": json.dumps(block.get("input", {})),
                        },
                    }
                )

        return result

    async def _call_together(
        self, conversation: list[dict], api_key: str, model: str
    ) -> dict:
        """Call Together AI with tool guidance embedded in system prompt.

        Together AI has limited function-calling support, so we embed tool
        descriptions in the system prompt and parse JSON responses.
        """
        import httpx

        timeout = httpx.Timeout(LLM_TIMEOUT, connect=10.0)

        messages = []
        for msg in conversation:
            role = msg["role"]
            if role == "system":
                messages.append({"role": "system", "content": msg.get("content", "")})
            elif role == "user":
                messages.append({"role": "user", "content": msg.get("content", "")})
            elif role == "assistant":
                content = msg.get("content", "")
                tool_calls = msg.get("tool_calls", [])
                if content:
                    messages.append({"role": "assistant", "content": content})
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    messages.append(
                        {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "tool_call": {
                                        "name": fn.get("name", ""),
                                        "arguments": json.loads(
                                            fn.get("arguments", "{}")
                                        ),
                                    }
                                }
                            ),
                        }
                    )
            elif role == "tool":
                messages.append(
                    {
                        "role": "user",
                        "content": f"Tool result: {msg.get('content', '')}",
                    }
                )

        body = {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": LLM_MAX_TOKENS,
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            response.raise_for_status()
            data = response.json()

        usage = data.get("usage", {})
        self._record_cost("together", usage)

        text = data["choices"][0]["message"]["content"] or ""

        # Strip code fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]

        # Try to detect if this is a tool call or final resolution
        result = {"content": text, "tool_calls": []}

        # For Together AI, we try to parse the response to detect tool calls
        # If the response is valid final resolution JSON, we return it as content
        # Otherwise we embed tool guidance in the text

        return result

    # ── Helpers ───────────────────────────────────────────────────────────

    def _format_tool_descriptions(self) -> str:
        """Format tool definitions as XML-like descriptions for the system prompt."""
        lines = []
        for t in TOOL_DEFINITIONS:
            params_desc = []
            props = t["parameters"].get("properties", {})
            required = t["parameters"].get("required", [])
            for pname, pinfo in props.items():
                req = " (required)" if pname in required else ""
                params_desc.append(f"      - {pname}: {pinfo.get('type', 'str')}{req}")
            lines.append(f'  <tool name="{t["name"]}">')
            lines.append(f"    <description>{t['description']}</description>")
            lines.append("    <parameters>")
            lines.extend(params_desc)
            lines.append("    </parameters>")
            lines.append("  </tool>")
        return "\n".join(lines)

    def _build_assistant_tool_call(self, tc: dict) -> dict:
        """Build an assistant message containing a tool call."""
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [tc] if tc.get("id") else [],
        }

    def _build_tool_result(self, tc: dict, tool_result: dict) -> dict:
        """Build a tool result message."""
        return {
            "role": "tool",
            "tool_call_id": tc.get("id", ""),
            "content": json.dumps(tool_result),
        }

    def _try_parse_resolution(self, text: str) -> dict | None:
        """Try to parse a final resolution JSON from LLM text response."""
        # Strip code fences
        content = text.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1] if "\n" in content else content[3:]
            if content.endswith("```"):
                content = content[:-3]

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        required = [
            "text_conflict",
            "conflict_note",
            "rag_result",
            "resolution",
            "confidence",
            "score_adjustment",
        ]
        for field in required:
            if field not in data:
                logger.warning("Missing field %s in agent resolution", field)
                return None

        # Validate types
        if not isinstance(data.get("text_conflict"), bool):
            return None
        if not isinstance(data.get("confidence"), (int, float)):
            return None
        if not isinstance(data.get("score_adjustment"), int):
            return None
        if data.get("rag_result") not in ("UNCERTAIN", "CONFIRMED", "NOT_NEEDED"):
            return None

        return data

    def _make_neutral_default(self, reason: str) -> dict:
        """Return a neutral default result with a note about why."""
        result = dict(_NEUTRAL_DEFAULT)
        result["conflict_note"] = (
            f"{_NEUTRAL_DEFAULT['conflict_note']} Reason: {reason}"
        )
        return result

    def _attach_usage(self, result: dict) -> dict:
        """Attach usage tracking metadata to the result."""
        result["_usage"] = {
            "tokens_in": self._tokens_in,
            "tokens_out": self._tokens_out,
            "cost_usd": round(self._cost_so_far, 6),
        }
        result["_agent"] = {
            "steps": self._step_count,
            "max_steps": self.max_steps,
        }
        return result

    def _record_cost(self, provider: str, usage: dict | int):
        """Accumulate cost from an API call.

        Accepts either a usage dict or token counts for mock mode.
        """
        if isinstance(usage, dict):
            prompt_tokens = (
                usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0) or 0
            )
            completion_tokens = (
                usage.get("completion_tokens", 0) or usage.get("output_tokens", 0) or 0
            )
        else:
            prompt_tokens = 0
            completion_tokens = usage if isinstance(usage, int) else 0

        rates = _COST_RATES.get(provider, {"input": 0.0, "output": 0.0})
        cost = (prompt_tokens / 1_000_000) * rates["input"] + (
            completion_tokens / 1_000_000
        ) * rates["output"]

        self._tokens_in += prompt_tokens
        self._tokens_out += completion_tokens
        self._cost_so_far += cost

    def _reset(self):
        """Reset per-evaluation state."""
        self._step_count = 0
        self._consecutive_tool_failures = 0
        self._cost_so_far = 0.0
        self._tokens_in = 0
        self._tokens_out = 0
