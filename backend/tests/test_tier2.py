"""
Comprehensive unit tests for the Tier 2 LLM pipeline.

Covers:
- build_prompt() — pure function, no mocking needed
- call_openai() — HTTP layer mocked via httpx.AsyncClient
- call_anthropic() — SDK mocked via anthropic.AsyncAnthropic
- call_together() — HTTP layer mocked via httpx.AsyncClient
- evaluate_tier_2() — orchestration, all three providers mocked
- _record_api_call() and get_cost_tracking() — pure accumulation logic
"""

import json

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

# ── Shared test data ─────────────────────────────────────────────────────

MOCK_TIER_2_RESULT = {
    "text_conflict": False,
    "conflict_note": "Mock: no conflict detected during unit test",
    "rag_result": "NOT_NEEDED",
    "resolution": "Unit test mock resolution. Defer to upstream score.",
    "confidence": 0.85,
    "score_adjustment": 0,
}

MOCK_USAGE = {
    "prompt_tokens": 150,
    "completion_tokens": 50,
    "total_tokens": 200,
}


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_cost_tracking():
    """Reset _cost_tracking before each test to avoid cross-test pollution."""
    from pipeline.tier_2 import _cost_tracking, _cost_lock

    with _cost_lock:
        saved = dict(_cost_tracking)
        _cost_tracking.update(
            {
                "total_calls": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_cached_tokens": 0,
                "estimated_cost_usd": 0.0,
            }
        )
    yield
    with _cost_lock:
        _cost_tracking.clear()
        _cost_tracking.update(saved)


def _mock_httpx_client(mock_client_cls):
    """Helper: configure an AsyncMock to act as a mocked httpx.AsyncClient.

    Returns the mock client instance so callers can set post.side_effect etc.
    """
    mock_client = AsyncMock()
    mock_client_cls.return_value = mock_client
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


def _ok_response(json_data=None):
    """Build a mock httpx.Response-like object for a 200 OK."""
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {}
    resp.json.return_value = json_data or {}
    return resp


# ═══════════════════════════════════════════════════════════════════════════
# 1. build_prompt tests
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildPrompt:
    """build_prompt() is a pure function — no mocking needed."""

    def test_returns_tuple(self):
        from pipeline.tier_2 import build_prompt

        sys_content, user_content = build_prompt(
            cve_id="CVE-2024-0001",
            cvss_score=9.1,
            description="Test description",
            rag_context="RAG context",
            cisa_kev=True,
            epss_score=0.95,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            upstream_scores={"exploitation_probability": "HIGH", "confidence": 0.9},
            mission_tags={
                "mission_prevalence": "Critical",
                "public_wellbeing_impact": "High",
            },
        )

        assert isinstance(sys_content, str)
        assert isinstance(user_content, str)
        assert len(sys_content) > 0
        assert len(user_content) > 0

    def test_system_content_contains_force_reflection(self):
        from pipeline.tier_2 import build_prompt

        sys_content, _ = build_prompt(
            cve_id="CVE-2024-0002",
            cvss_score=7.5,
            description="desc",
            rag_context="ctx",
            cisa_kev=False,
            epss_score=0.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            upstream_scores={},
            mission_tags={},
        )

        assert "text conflict" in sys_content.lower()
        assert "exploitability" in sys_content.lower()
        assert (
            "Western Australian" in sys_content
            or "WA government" in sys_content
            or "Western Australia" in sys_content
        )
        assert "text_conflict" in sys_content
        assert "JSON" in sys_content.upper() or "json" in sys_content.lower()

    def test_user_content_contains_cve_id_and_score(self):
        from pipeline.tier_2 import build_prompt

        _, user_content = build_prompt(
            cve_id="CVE-2024-TEST01",
            cvss_score=6.2,
            description="Memory corruption in parser",
            rag_context="No relevant documents found.",
            cisa_kev=False,
            epss_score=0.12,
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
            upstream_scores={"exploitation_probability": "MEDIUM", "confidence": 0.65},
            mission_tags={
                "mission_prevalence": "Support",
                "public_wellbeing_impact": "Minimal",
            },
        )

        assert "CVE-2024-TEST01" in user_content
        assert "6.2" in user_content
        assert "Memory corruption" in user_content
        assert "MEDIUM" in user_content or "exploitation" in user_content

    def test_user_content_includes_cwe_block_when_provided(self):
        from pipeline.tier_2 import build_prompt

        _, user_content = build_prompt(
            cve_id="CVE-2024-0003",
            cvss_score=5.0,
            description="desc",
            rag_context="ctx",
            cisa_kev=False,
            epss_score=0.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            upstream_scores={},
            mission_tags={},
            cwe_result={
                "cwe_pillar": "Pillar",
                "cwe_class": "Class",
                "cwe_base": "Base",
                "cwe_variant": "Variant",
            },
        )

        assert "CWE Pillar" in user_content
        assert "cwe_base" in user_content or "CWE Base" in user_content


# ═══════════════════════════════════════════════════════════════════════════
# 2. call_openai tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCallOpenAI:
    """Mock httpx.AsyncClient at the class level."""

    @patch("httpx.AsyncClient")
    async def test_success(self, mock_client_cls):
        """Happy path: valid JSON response → parsed dict."""
        from pipeline.tier_2 import call_openai

        client = _mock_httpx_client(mock_client_cls)
        client.post.return_value = _ok_response(
            {
                "choices": [{"message": {"content": json.dumps(MOCK_TIER_2_RESULT)}}],
                "usage": MOCK_USAGE,
            }
        )

        result, usage = await call_openai("sys", "user", "sk-test", "gpt-4o-mini")

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.85
        assert result["rag_result"] == "NOT_NEEDED"
        assert usage["tokens_in"] == 150
        assert usage["tokens_out"] == 50
        assert usage["cost_usd"] > 0.0
        client.post.assert_called_once()

    @patch("httpx.AsyncClient")
    async def test_content_filter_raises_value_error(self, mock_client_cls):
        """finish_reason == 'content_filter' → raises ValueError."""
        from pipeline.tier_2 import call_openai

        client = _mock_httpx_client(mock_client_cls)
        client.post.return_value = _ok_response(
            {
                "choices": [
                    {
                        "finish_reason": "content_filter",
                        "message": {
                            "content": None,
                            "refusal": "Our system flagged this content",
                        },
                    }
                ],
                "usage": MOCK_USAGE,
            }
        )

        with pytest.raises(ValueError, match="content filter refusal"):
            await call_openai("sys", "user", "sk-test", "gpt-4o-mini")

    @patch("httpx.AsyncClient")
    async def test_429_retry_then_succeeds(self, mock_client_cls):
        """429 rate limit → retries → succeeds on second attempt."""
        import httpx

        from pipeline.tier_2 import call_openai

        client = _mock_httpx_client(mock_client_cls)

        # First response: 429
        error_resp = MagicMock()
        error_resp.status_code = 429
        error_resp.headers = {"Retry-After": "0.01"}
        error_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429 rate limit",
            request=MagicMock(),
            response=error_resp,
        )

        # Second response: 200 OK
        success_resp = _ok_response(
            {
                "choices": [{"message": {"content": json.dumps(MOCK_TIER_2_RESULT)}}],
                "usage": MOCK_USAGE,
            }
        )

        client.post.side_effect = [error_resp, success_resp]

        result, usage = await call_openai("sys", "user", "sk-test", "gpt-4o-mini")

        assert result["text_conflict"] is False
        assert usage["tokens_in"] == 150
        assert client.post.call_count == 2

    @patch("httpx.AsyncClient")
    async def test_5xx_retry_then_succeeds(self, mock_client_cls):
        """5xx server error → retries → succeeds on third attempt."""
        import httpx

        from pipeline.tier_2 import call_openai

        client = _mock_httpx_client(mock_client_cls)

        def _make_500():
            resp = MagicMock()
            resp.status_code = 500
            resp.headers = {}
            resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                "500 Server Error",
                request=MagicMock(),
                response=resp,
            )
            return resp

        success_resp = _ok_response(
            {
                "choices": [{"message": {"content": json.dumps(MOCK_TIER_2_RESULT)}}],
                "usage": MOCK_USAGE,
            }
        )

        # Two failures, then success
        client.post.side_effect = [_make_500(), _make_500(), success_resp]

        result, usage = await call_openai("sys", "user", "sk-test", "gpt-4o-mini")

        assert result["text_conflict"] is False
        assert usage["tokens_in"] == 150
        assert client.post.call_count == 3

    @patch("httpx.AsyncClient")
    async def test_missing_required_fields_raises_value_error(self, mock_client_cls):
        """Response JSON missing a required field → ValueError."""
        from pipeline.tier_2 import call_openai

        client = _mock_httpx_client(mock_client_cls)

        # Missing "rag_result", "resolution", "confidence", "score_adjustment"
        partial = {
            "text_conflict": False,
            "conflict_note": "Partial result",
        }
        client.post.return_value = _ok_response(
            {
                "choices": [{"message": {"content": json.dumps(partial)}}],
                "usage": MOCK_USAGE,
            }
        )

        with pytest.raises(ValueError, match="Missing field"):
            await call_openai("sys", "user", "sk-test", "gpt-4o-mini")


# ═══════════════════════════════════════════════════════════════════════════
# 3. call_anthropic tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCallAnthropic:
    """Mock anthropic.AsyncAnthropic (the class imported inside the function)."""

    @patch("anthropic.AsyncAnthropic")
    async def test_success(self, mock_anthropic_cls):
        """Happy path: parsed_output.model_dump() returns valid dict."""
        from pipeline.tier_2 import call_anthropic

        mock_client = AsyncMock()
        mock_anthropic_cls.return_value = mock_client

        mock_parsed = MagicMock()
        mock_parsed.parsed_output.model_dump.return_value = dict(MOCK_TIER_2_RESULT)
        # Simulate Anthropic usage object
        mock_parsed.usage = MagicMock()
        mock_parsed.usage.input_tokens = 150
        mock_parsed.usage.output_tokens = 50
        mock_parsed.usage.cache_read_input_tokens = None

        mock_client.messages.parse.return_value = mock_parsed

        result, usage = await call_anthropic(
            "sys", "user", "sk-ant-api03-test", "claude-haiku-4-5"
        )

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.85
        assert usage["tokens_in"] == 150
        assert usage["tokens_out"] == 50
        mock_client.messages.parse.assert_called_once()

    @patch("anthropic.AsyncAnthropic")
    async def test_refusal_raises_value_error(self, mock_anthropic_cls):
        """stop_reason == 'refusal' → raises ValueError."""
        from pipeline.tier_2 import call_anthropic

        mock_client = AsyncMock()
        mock_anthropic_cls.return_value = mock_client

        mock_refused = MagicMock()
        mock_refused.parsed_output = None
        mock_refused.stop_reason = "refusal"

        mock_client.messages.parse.return_value = mock_refused

        with pytest.raises(ValueError, match="refusal"):
            await call_anthropic("sys", "user", "sk-ant-api03-test", "claude-haiku-4-5")

    @patch("anthropic.AsyncAnthropic")
    async def test_rate_limit_retry_then_succeeds(self, mock_anthropic_cls):
        """RateLimitError on first call → retries → succeeds on second."""
        from anthropic import RateLimitError

        from pipeline.tier_2 import call_anthropic

        mock_client = AsyncMock()
        mock_anthropic_cls.return_value = mock_client

        # Build a proper RateLimitError
        rate_limit_resp = MagicMock()
        rate_limit_resp.headers = {"retry-after": "0.01"}
        rate_limit_resp.status_code = 429
        rate_limit_err = RateLimitError(
            message="Rate limited",
            response=rate_limit_resp,
            body=None,
        )

        # Successful parse
        mock_parsed = MagicMock()
        mock_parsed.parsed_output.model_dump.return_value = dict(MOCK_TIER_2_RESULT)
        mock_parsed.usage = MagicMock()
        mock_parsed.usage.input_tokens = 100
        mock_parsed.usage.output_tokens = 30
        mock_parsed.usage.cache_read_input_tokens = None

        mock_client.messages.parse.side_effect = [rate_limit_err, mock_parsed]

        result, usage = await call_anthropic(
            "sys", "user", "sk-ant-api03-test", "claude-haiku-4-5"
        )

        assert result["text_conflict"] is False
        assert usage["tokens_in"] == 100
        assert usage["tokens_out"] == 30
        assert mock_client.messages.parse.call_count == 2


# ═══════════════════════════════════════════════════════════════════════════
# 4. call_together tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCallTogether:
    """Mock httpx.AsyncClient at the class level."""

    @patch("httpx.AsyncClient")
    async def test_success_with_markdown_fences(self, mock_client_cls):
        """Happy path: response wraps JSON in ```json ... ``` fences → stripped."""
        from pipeline.tier_2 import call_together

        client = _mock_httpx_client(mock_client_cls)

        fence_content = f"```json\n{json.dumps(MOCK_TIER_2_RESULT)}\n```"
        client.post.return_value = _ok_response(
            {
                "choices": [{"message": {"content": fence_content}}],
                "usage": MOCK_USAGE,
            }
        )

        result, usage = await call_together(
            "sys", "user", "sk-together-test", "meta-llama/Llama-3.3-70B-Instruct-Turbo"
        )

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.85
        assert usage["tokens_in"] == 150
        assert usage["tokens_out"] == 50

    @patch("pipeline.tier_2.single._together_supports_json_schema")
    @patch("httpx.AsyncClient")
    async def test_non_json_schema_model(self, mock_client_cls, mock_schema_check):
        """Model NOT in TOGETHER_JSON_SCHEMA_MODELS → response_format omitted."""
        from pipeline.tier_2 import call_together

        mock_schema_check.return_value = False

        client = _mock_httpx_client(mock_client_cls)
        client.post.return_value = _ok_response(
            {
                "choices": [{"message": {"content": json.dumps(MOCK_TIER_2_RESULT)}}],
                "usage": MOCK_USAGE,
            }
        )

        result, usage = await call_together(
            "sys", "user", "sk-together-test", "some-unknown-model"
        )

        assert result["text_conflict"] is False
        assert usage["tokens_in"] == 150
        mock_schema_check.assert_called_once_with("some-unknown-model")

        # Verify that response_format was NOT in the request body
        _call_args = client.post.call_args
        if _call_args:
            _, kwargs = _call_args
            assert "response_format" not in kwargs.get("json", {})

    @patch("httpx.AsyncClient")
    async def test_invalid_json_response(self, mock_client_cls):
        """Response contains invalid JSON → raises ValueError."""
        from pipeline.tier_2 import call_together

        client = _mock_httpx_client(mock_client_cls)
        client.post.return_value = _ok_response(
            {
                "choices": [{"message": {"content": "not valid json {{{"}}],
                "usage": MOCK_USAGE,
            }
        )

        with pytest.raises((ValueError, json.JSONDecodeError)):
            await call_together(
                "sys",
                "user",
                "sk-together-test",
                "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            )


# ═══════════════════════════════════════════════════════════════════════════
# 5. evaluate_tier_2 orchestration tests
# ═══════════════════════════════════════════════════════════════════════════


class TestEvaluateTier2:
    """Mock all three provider functions at their definition site."""

    _COMMON_ARGS = dict(
        cve_id="CVE-2024-TEST-EVAL",
        hostname="test.wa.gov.au",
        cvss_score=7.5,
        description="Orchestration test vulnerability",
        rag_context="No context",
        cisa_kev=False,
        epss_score=0.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        upstream_scores={"exploitation_probability": "HIGH", "confidence": 0.8},
        mission_tags={
            "mission_prevalence": "Critical",
            "public_wellbeing_impact": "High",
        },
    )

    _MOCK_USAGE_RETURN = {"tokens_in": 100, "tokens_out": 50, "cost_usd": 0.0001}

    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_anthropic", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_together", new_callable=AsyncMock)
    async def test_primary_provider_succeeds(
        self, mock_together, mock_anthropic, mock_openai
    ):
        """Primary (openai) succeeds → returns result, backup never called."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_openai.return_value = (
            dict(MOCK_TIER_2_RESULT),
            dict(self._MOCK_USAGE_RETURN),
        )

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.85
        mock_openai.assert_called_once()
        mock_anthropic.assert_not_called()
        mock_together.assert_not_called()

    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_anthropic", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_together", new_callable=AsyncMock)
    async def test_all_providers_fail_known_conflict(
        self, mock_together, mock_anthropic, mock_openai
    ):
        """All providers fail + CVE in KNOWN_CONFLICTS → cached resolution with note."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_openai.side_effect = Exception("OpenAI unavailable")
        # These won't actually be called (no backup provider configured),
        # but set them up to fail just in case.
        mock_anthropic.side_effect = Exception("Anthropic unavailable")
        mock_together.side_effect = Exception("Together unavailable")

        result = await evaluate_tier_2(
            cve_id="CVE-2023-36884",
            **{k: v for k, v in self._COMMON_ARGS.items() if k != "cve_id"},
        )

        assert result["text_conflict"] is True
        assert "[Note:" in result["conflict_note"]
        assert "Cloud LLM" in result["conflict_note"]
        assert result["confidence"] == 0.72

    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_anthropic", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_together", new_callable=AsyncMock)
    async def test_all_providers_fail_neutral_default(
        self, mock_together, mock_anthropic, mock_openai
    ):
        """All providers fail + CVE NOT in KNOWN_CONFLICTS → neutral default (conf 0.30)."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_openai.side_effect = Exception("OpenAI unavailable")
        mock_anthropic.side_effect = Exception("Anthropic unavailable")
        mock_together.side_effect = Exception("Together unavailable")

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.30
        assert result["score_adjustment"] == 0
        assert result["rag_result"] == "NOT_QUERIED"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Cost tracking tests
# ═══════════════════════════════════════════════════════════════════════════


class TestCostTracking:
    """_record_api_call() and get_cost_tracking() — pure accumulation logic."""

    def test_record_api_call_accumulates(self):
        """Multiple calls to _record_api_call correctly accumulate all counters."""
        from pipeline.tier_2 import _record_api_call, _cost_tracking

        _record_api_call(
            "openai",
            "gpt-4o-mini",
            {"prompt_tokens": 100, "completion_tokens": 50, "cached_tokens": 10},
        )

        assert _cost_tracking["total_calls"] == 1
        assert _cost_tracking["total_input_tokens"] == 100
        assert _cost_tracking["total_output_tokens"] == 50
        assert _cost_tracking["total_cached_tokens"] == 10
        assert _cost_tracking["estimated_cost_usd"] > 0.0

        # Second call
        _record_api_call(
            "anthropic",
            "claude-haiku-4-5",
            {"input_tokens": 200, "output_tokens": 75, "cached_tokens": 5},
        )

        assert _cost_tracking["total_calls"] == 2
        assert _cost_tracking["total_input_tokens"] == 300  # 100 + 200
        assert _cost_tracking["total_output_tokens"] == 125  # 50 + 75
        assert _cost_tracking["total_cached_tokens"] == 15  # 10 + 5

    def test_record_api_call_handles_empty_usage(self):
        """Call with empty usage dict does not break and adds zero cost."""
        from pipeline.tier_2 import _record_api_call, _cost_tracking

        _record_api_call("together", "llama", {})

        assert _cost_tracking["total_calls"] == 1
        assert _cost_tracking["total_input_tokens"] == 0
        assert _cost_tracking["total_output_tokens"] == 0
        assert _cost_tracking["estimated_cost_usd"] == 0.0

    def test_get_cost_tracking_returns_snapshot(self):
        """get_cost_tracking() returns a dict with all expected keys."""
        from pipeline.tier_2 import get_cost_tracking, _record_api_call

        _record_api_call(
            "openai", "gpt-4o-mini", {"prompt_tokens": 500, "completion_tokens": 100}
        )

        snapshot = get_cost_tracking()

        assert isinstance(snapshot, dict)
        assert "total_calls" in snapshot
        assert "total_input_tokens" in snapshot
        assert "total_output_tokens" in snapshot
        assert "total_cached_tokens" in snapshot
        assert "estimated_cost_usd" in snapshot
        assert snapshot["total_calls"] == 1

        # Verify it's a copy, not mutable reference
        snapshot["total_calls"] = 999
        assert get_cost_tracking()["total_calls"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# 7. Agent Feature Flag Integration Tests (Sprint 20)
# ═══════════════════════════════════════════════════════════════════════════


class TestEvaluateTier2WithAgent:
    """Test evaluate_tier_2() interaction with the AgenticEvaluator feature flag."""

    _COMMON_ARGS = dict(
        cve_id="CVE-2024-TEST-AGENT",
        hostname="test.wa.gov.au",
        cvss_score=7.5,
        description="Agent integration test vulnerability",
        rag_context="test.wa.gov.au some RAG context",
        cisa_kev=False,
        epss_score=0.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        upstream_scores={"exploitation_probability": "HIGH", "confidence": 0.8},
        mission_tags={
            "mission_prevalence": "Critical",
            "public_wellbeing_impact": "High",
        },
    )

    @patch("pipeline.tier_2.single.AGENT_ENABLED", True)
    @patch("pipeline.tier_2.agent.AgenticEvaluator.evaluate", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    async def test_agent_enabled_uses_agent_evaluator(
        self, mock_openai, mock_agent_evaluate
    ):
        """When AGENT_ENABLED is True, the AgenticEvaluator is used."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_agent_result = {
            "text_conflict": False,
            "conflict_note": "Agent resolved",
            "rag_result": "NOT_NEEDED",
            "resolution": "Agent resolution",
            "confidence": 0.90,
            "score_adjustment": 0,
            "_usage": {"tokens_in": 500, "tokens_out": 200, "cost_usd": 0.001},
            "_agent": {"steps": 3, "max_steps": 15},
        }
        mock_agent_evaluate.return_value = mock_agent_result

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        mock_agent_evaluate.assert_called_once()
        mock_openai.assert_not_called()
        assert result["text_conflict"] is False
        assert result["confidence"] == 0.90
        assert result["_usage"]["tokens_in"] == 500

    @patch("pipeline.tier_2.single.AGENT_ENABLED", True)
    @patch("pipeline.tier_2.agent.AgenticEvaluator.evaluate", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    async def test_agent_falls_back_to_single_shot(
        self, mock_openai, mock_agent_evaluate
    ):
        """When agent fails, evaluate_tier_2 falls back to single-shot."""
        from pipeline.tier_2 import evaluate_tier_2

        # Agent raises an exception
        mock_agent_evaluate.side_effect = Exception("Agent failed")

        # Mock single-shot to succeed
        mock_openai.return_value = (
            {
                "text_conflict": False,
                "conflict_note": "Single-shot resolved after agent fail",
                "rag_result": "NOT_NEEDED",
                "resolution": "Fallback resolution",
                "confidence": 0.75,
                "score_adjustment": 0,
            },
            {"tokens_in": 100, "tokens_out": 50, "cost_usd": 0.0001},
        )

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        assert result is not None
        assert result["text_conflict"] is False
        assert result["confidence"] == 0.75
        assert "single-shot" in result.get("conflict_note", "").lower()

    @patch("pipeline.tier_2.single.AGENT_ENABLED", False)
    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    async def test_agent_disabled_uses_single_shot(self, mock_openai):
        """When AGENT_ENABLED is False, single-shot is used."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_openai.return_value = (
            {
                "text_conflict": False,
                "conflict_note": "Single-shot resolved",
                "rag_result": "NOT_NEEDED",
                "resolution": "Single-shot",
                "confidence": 0.80,
                "score_adjustment": 0,
            },
            {"tokens_in": 100, "tokens_out": 50, "cost_usd": 0.0001},
        )

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        mock_openai.assert_called_once()
        assert result["text_conflict"] is False
        assert result["confidence"] == 0.80

    @patch("pipeline.tier_2.single.AGENT_ENABLED", True)
    @patch("pipeline.tier_2.agent.AgenticEvaluator.evaluate", new_callable=AsyncMock)
    @patch("pipeline.tier_2.single.call_openai", new_callable=AsyncMock)
    async def test_agent_cost_tracking(self, mock_openai, mock_agent_evaluate):
        """Cost tracking works when agent is used."""
        from pipeline.tier_2 import evaluate_tier_2

        mock_agent_result = {
            "text_conflict": False,
            "conflict_note": "Agent resolved",
            "rag_result": "NOT_NEEDED",
            "resolution": "Agent resolution",
            "confidence": 0.90,
            "score_adjustment": 0,
            "_usage": {"tokens_in": 500, "tokens_out": 200, "cost_usd": 0.001},
            "_agent": {"steps": 3, "max_steps": 15},
        }
        mock_agent_evaluate.return_value = mock_agent_result

        result = await evaluate_tier_2(**self._COMMON_ARGS)

        # The agent tracks its own cost separately from the module-level cost tracking
        assert result["_usage"]["cost_usd"] == 0.001
        assert result["_usage"]["tokens_in"] == 500
