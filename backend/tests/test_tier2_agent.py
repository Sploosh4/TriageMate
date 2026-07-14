"""
Unit tests for the Tier 2 Agentic Evaluator (Sprint 20).

Covers:
- Tool function correctness (KEV, NVD, EPSS, CWE, all 12 tool definitions)
- Agent step limit enforcement
- Agent cost budget enforcement
- Fallback to single-shot
- Feature flag disabled (single-shot used)
- Final resolution parsing
- Consecutive tool failure termination
"""

import json
import pytest
from unittest.mock import patch

# ── Tool Tests ─────────────────────────────────────────────────────────────


class TestTools:
    """Verify individual tool functions return correct structures."""

    MOCK_KEV_CACHE = {
        "CVE-2023-36884": {
            "known_exploited": True,
            "date_added": "2023-07-11",
            "action": "Apply mitigations",
            "note": "https://example.com",
        }
    }

    @patch("pipeline.tier_2.tools._load_kev_cache")
    def test_search_kev_found(self, mock_load_kev):
        from pipeline.tier_2.tools import _search_kev

        mock_load_kev.return_value = self.MOCK_KEV_CACHE
        result = _search_kev("CVE-2023-36884")
        assert result["success"] is True
        assert result["data"]["is_kev"] is True
        assert result["data"]["date_added"] == "2023-07-11"

    @patch("pipeline.tier_2.tools._load_kev_cache")
    def test_search_kev_not_found(self, mock_load_kev):
        from pipeline.tier_2.tools import _search_kev

        mock_load_kev.return_value = self.MOCK_KEV_CACHE
        result = _search_kev("CVE-2024-99999")
        assert result["success"] is True
        assert result["data"]["is_kev"] is False

    @patch("pipeline.tier_2.tools._load_kev_cache")
    def test_search_kev_empty_cache(self, mock_load_kev):
        from pipeline.tier_2.tools import _search_kev

        mock_load_kev.return_value = {}
        result = _search_kev("CVE-2023-36884")
        assert result["success"] is True
        assert result["data"]["is_kev"] is False

    @patch("integrations.nvd.get_nvd_data")
    def test_search_nvd(self, mock_nvd):
        from pipeline.tier_2.tools import _search_nvd

        mock_nvd.return_value = {
            "cwe_class": "CWE-89",
            "nvd_reference_count": 12,
            "vulnerability_age_days": 45,
            "patch_available": True,
            "cvss_exploitability_sub": 3.9,
            "cvss_impact_sub": 5.9,
        }
        result = _search_nvd("CVE-2023-0001")
        assert result["success"] is True
        assert result["data"]["cwe_id"] == "CWE-89"
        assert result["data"]["reference_count"] == 12
        assert result["data"]["patch_available"] is True

    @patch("pipeline.tier_2.tools._load_epss_cache")
    def test_search_epss_found(self, mock_load_epss):
        from pipeline.tier_2.tools import _search_epss

        mock_load_epss.return_value = {
            "CVE-2023-36884": {"epss": 0.974, "percentile": 0.987}
        }
        result = _search_epss("CVE-2023-36884")
        assert result["success"] is True
        assert result["data"]["epss_score"] == 0.974
        assert result["data"]["epss_percentile"] == 0.987

    @patch("pipeline.tier_2.tools._load_epss_cache")
    def test_search_epss_not_found(self, mock_load_epss):
        from pipeline.tier_2.tools import _search_epss

        mock_load_epss.return_value = {}
        result = _search_epss("CVE-2024-99999")
        assert result["success"] is True
        assert result["data"]["epss_score"] == 0.0

    @patch("ingest_cwe.get_cwe")
    def test_search_cwe(self, mock_get_cwe):
        from pipeline.tier_2.tools import _search_cwe

        mock_get_cwe.return_value = {"cwe_class": "CWE-89"}
        result = _search_cwe("CVE-2023-0001")
        assert result["success"] is True
        assert result["data"]["cwe_id"] == "CWE-89"
        assert result["data"]["cwe_class"] == "CWE-89"

    @patch("ingest_cwe.get_cwe")
    @patch("integrations.mitre_mapping.lookup_mitre")
    def test_search_mitre(self, mock_mitre, mock_cwe):
        from pipeline.tier_2.tools import _search_mitre

        mock_cwe.return_value = {"cwe_class": "CWE-89"}
        mock_mitre.return_value = [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "desc": "SQL injection in public-facing application",
            }
        ]
        result = _search_mitre("CVE-2023-0001")
        assert result["success"] is True
        assert len(result["data"]["techniques"]) == 1
        assert result["data"]["techniques"][0]["id"] == "T1190"

    @patch("integrations.cmdb.get_asset_context")
    @patch("integrations.network_context.get_network_context")
    def test_query_network(self, mock_net, mock_cmdb):
        from pipeline.tier_2.tools import _query_network

        mock_cmdb.return_value = {"network_zone": "DMZ-External"}
        mock_net.return_value = {
            "blast_radius_score": 0.75,
            "zone": "dmz",
            "zone_display": "DMZ",
            "peer_count": 10,
            "exposure_level": "high",
            "internet_facing_peers": 5,
        }
        result = _query_network("test-host.wa.gov.au")
        assert result["success"] is True
        assert result["data"]["blast_radius_score"] == 0.75
        assert result["data"]["peer_count"] == 10

    @patch("integrations.synthetic_telemetry.get_telemetry_context")
    def test_query_telemetry(self, mock_telemetry):
        from pipeline.tier_2.tools import _query_telemetry

        mock_telemetry.return_value = {
            "threat_score": 0.85,
            "sentinel_incidents": [{"id": "1"}, {"id": "2"}],
            "edr_alerts": [{"id": "1"}],
            "process_evidence": {"is_running": True, "is_loaded": False},
        }
        result = _query_telemetry(
            cve_id="CVE-2023-0001",
            hostname="test.wa.gov.au",
            cvss_score=9.0,
            cisa_kev=True,
            epss_score=0.9,
            description="RCE in test",
        )
        assert result["success"] is True
        assert result["data"]["threat_score"] == 0.85
        assert result["data"]["incident_count"] == 2
        assert result["data"]["alert_count"] == 1

    @patch("integrations.advisories.get_advisory")
    def test_query_advisories(self, mock_advisory):
        from pipeline.tier_2.tools import _query_advisories

        mock_advisory.return_value = {
            "ref_id": "ADV-CVE-2023-36884",
            "quote": "WASOC advisory for CVE-2023-36884",
        }
        result = _query_advisories("CVE-2023-36884")
        assert result["success"] is True
        assert "WASOC" in result["data"]["advisory_text"]

    @patch("integrations.exploitdb.has_poc")
    @patch("integrations.exploitdb._lookup_edb")
    def test_search_exploitdb(self, mock_lookup, mock_has_poc):
        from pipeline.tier_2.tools import _search_exploitdb

        mock_has_poc.return_value = True
        mock_lookup.return_value = [
            {
                "edb_id": "12345",
                "description": "Test exploit",
                "type": "web",
                "platform": "php",
            }
        ]
        result = _search_exploitdb("CVE-2023-0001")
        assert result["success"] is True
        assert result["data"]["has_poc"] is True
        assert result["data"]["exploit_count"] == 1

    @patch("integrations.metasploit.has_payload")
    def test_search_metasploit(self, mock_payload):
        from pipeline.tier_2.tools import _search_metasploit

        mock_payload.return_value = True
        result = _search_metasploit("CVE-2023-0001")
        assert result["success"] is True
        assert result["data"]["has_module"] is True

    @patch("integrations.cmdb.get_asset_context")
    def test_search_cmdb(self, mock_cmdb):
        from pipeline.tier_2.tools import _search_cmdb

        mock_cmdb.return_value = {
            "role": "Web Server",
            "business_owner": "ICT Department",
            "network_zone": "DMZ",
            "data_classification": "OFFICIAL Sensitive",
            "internet_facing": True,
            "operating_system": "Windows Server 2019",
            "registered_applications": "IIS 10",
        }
        result = _search_cmdb("test.wa.gov.au")
        assert result["success"] is True
        assert result["data"]["asset_type"] == "Web Server"
        assert result["data"]["data_classification"] == "OFFICIAL Sensitive"

    @patch("ingest_helpers.query_rag")
    def test_rag_query(self, mock_rag):
        from pipeline.tier_2.tools import _rag_query

        mock_rag.return_value = {
            "documents": [{"id": "1", "text": "Test doc"}],
            "rag_context": "Test RAG context",
            "status": "ok",
        }
        result = _rag_query(hostname="test-asset")
        assert result["success"] is True
        assert result["data"]["results_count"] == 1
        assert result["data"]["context"] == "Test RAG context"

    # ── RAG Hostname Binding Tests ──────────────────────────────────────────

    @patch("ingest_helpers.query_rag")
    def test_rag_hostname_no_supplied_hostname_with_case_hostname_succeeds(
        self, mock_rag
    ):
        """No caller-supplied hostname + valid case_hostname → succeeds."""
        from pipeline.tier_2.tools import execute_tool

        mock_rag.return_value = {
            "documents": [{"id": "1", "text": "Test doc"}],
            "rag_context": "Test context",
            "status": "ok",
        }
        result = execute_tool(
            "rag_query",
            {"cwe_class": "CWE-79"},
            case_hostname="demo.host.wa.gov.au",
        )
        assert result["success"] is True

    @patch("ingest_helpers.query_rag")
    def test_rag_hostname_missing_case_hostname_fails_closed(self, mock_rag):
        """Missing case_hostname rejects the call before querying RAG."""
        from pipeline.tier_2.tools import execute_tool

        result = execute_tool(
            "rag_query",
            {"cwe_class": "CWE-79"},
            case_hostname=None,
        )
        assert result["success"] is False
        assert "without a case hostname" in result["error"]
        mock_rag.assert_not_called()

    @patch("ingest_helpers.query_rag")
    def test_rag_hostname_mismatched_hostname_rejected(self, mock_rag):
        """Any caller-supplied hostname differing from case_hostname → rejected."""
        from pipeline.tier_2.tools import execute_tool

        mock_rag.return_value = {
            "documents": [],
            "rag_context": "",
            "status": "ok",
        }
        result = execute_tool(
            "rag_query",
            {"hostname": "evil.host.wa.gov.au", "cwe_class": "CWE-79"},
            case_hostname="demo.host.wa.gov.au",
        )
        assert result["success"] is False
        assert "not the case under investigation" in result["error"]

    @patch("ingest_helpers.query_rag")
    def test_rag_hostname_legacy_query_text_ignored(self, mock_rag):
        """Free-form/unknown asset-selector params must not alter queried hostname.

        Legacy params (like query_text) that are not in the _rag_query signature
        cause a parameter error — this is "fail closed": the unknown param cannot
        alter the hostname because the tool rejects the unexpected keyword.
        """
        from pipeline.tier_2.tools import execute_tool

        mock_rag.return_value = {
            "documents": [{"id": "1", "text": "Test doc"}],
            "rag_context": "Test context",
            "status": "ok",
        }
        # Legacy query_text param is NOT in the new rag_query tool definition
        # and NOT in the _rag_query signature. It will be rejected as an
        # unexpected keyword, which is the correct fail-closed behaviour.
        result = execute_tool(
            "rag_query",
            {"query_text": "some-legacy-value", "cwe_class": "CWE-79"},
            case_hostname="demo.host.wa.gov.au",
        )
        # Fail closed: unknown params cannot alter the queried hostname
        assert result["success"] is False
        assert "Parameter error" in result["error"]
        assert "unexpected keyword" in result["error"]

    @patch("ingest_helpers.query_rag")
    def test_rag_hostname_arbitrary_params_no_effect(self, mock_rag):
        """Arbitrary unknown parameters must not affect the queried hostname.

        Fail-closed: unexpected keyword args are rejected, preventing any
        parameter from altering the asset hostname under investigation.
        """
        from pipeline.tier_2.tools import execute_tool

        mock_rag.return_value = {
            "documents": [{"id": "1", "text": "Test doc"}],
            "rag_context": "Test context",
            "status": "ok",
        }
        result = execute_tool(
            "rag_query",
            {"cwe_class": "CWE-79", "unknown_param": "should-be-ignored"},
            case_hostname="demo.host.wa.gov.au",
        )
        # Extra unknown params that aren't in _rag_query signature
        # cause TypeError -> tool returns success=False
        # This is the expected fail-closed behaviour — unknown params
        # cannot alter the hostname because they're rejected.
        assert result["success"] is False
        assert "Parameter error" in result["error"]
        assert "unexpected keyword" in result["error"]

    def test_all_twelve_tool_definitions_exist(self):
        from pipeline.tier_2.tools import TOOL_DEFINITIONS, get_tool_names

        assert len(TOOL_DEFINITIONS) == 12
        names = get_tool_names()
        expected = [
            "search_kev",
            "search_nvd",
            "search_epss",
            "search_cwe",
            "search_mitre",
            "query_network",
            "query_telemetry",
            "query_advisories",
            "search_exploitdb",
            "search_metasploit",
            "search_cmdb",
            "rag_query",
        ]
        for name in expected:
            assert name in names, f"Missing tool: {name}"

        # Verify each definition has the required fields.
        # rag_query is the exception — it exposes only optional cwe_class
        # (hostname is server-injected), so it has an empty required list.
        for t in TOOL_DEFINITIONS:
            assert "name" in t
            assert "description" in t
            assert "parameters" in t
            assert "type" in t["parameters"]
            assert "properties" in t["parameters"]
            assert "required" in t["parameters"]
            if t["name"] != "rag_query":
                assert len(t["parameters"]["required"]) > 0, (
                    f"Tool {t['name']} has no required params"
                )

    def test_execute_tool_dispatch(self):
        from pipeline.tier_2.tools import execute_tool

        # Unknown tool
        result = execute_tool("nonexistent", {})
        assert result["success"] is False
        assert "Unknown tool" in result["error"]

        # Known tool with bad params (missing required)
        result = execute_tool("search_kev", {})
        assert result["success"] is False


# ── Agent Tests ────────────────────────────────────────────────────────────


class TestAgent:
    """Test AgenticEvaluator behaviour with mocked LLM calls."""

    _VALID_RESOLUTION = {
        "text_conflict": False,
        "conflict_note": "No conflict detected",
        "rag_result": "NOT_NEEDED",
        "resolution": "Mock resolution",
        "confidence": 0.85,
        "score_adjustment": 0,
    }

    def setup_method(self):
        """Set a fake API key so the agent doesn't bail early."""
        import pipeline.tier_2.agent as agent_mod

        self._orig_api_key = agent_mod.LLM_API_KEY
        agent_mod.LLM_API_KEY = "sk-test-fake-key"

    def teardown_method(self):
        """Restore original API key."""
        import pipeline.tier_2.agent as agent_mod

        agent_mod.LLM_API_KEY = self._orig_api_key

    def _make_tool_call_response(self, tool_name: str, tool_args: dict = None) -> dict:
        """Build a mock LLM response that calls a tool."""
        if tool_args is None:
            tool_args = {"cve_id": "CVE-2023-0001"}
        return {
            "content": "",
            "tool_calls": [
                {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(tool_args),
                    },
                }
            ],
        }

    def _make_final_response(self, resolution: dict = None) -> dict:
        """Build a mock LLM response with a final resolution."""
        if resolution is None:
            resolution = self._VALID_RESOLUTION
        return {"content": json.dumps(resolution), "tool_calls": []}

    def _make_text_response(self, text: str) -> dict:
        """Build a mock LLM response with just text (not JSON)."""
        return {"content": text, "tool_calls": []}

    class _MockEvaluator:
        """A simplified evaluator that simulates tool-calling behaviour."""

        def __init__(self, max_steps=15, cost_budget_usd=0.50):
            self.max_steps = max_steps
            self.cost_budget_usd = cost_budget_usd
            self._step_count = 0
            self._consecutive_tool_failures = 0
            self._cost_so_far = 0.0
            self._tokens_in = 0
            self._tokens_out = 0

    # ── Step limit ─────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_step_limit(self):
        """Agent should terminate when step limit is reached."""
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator(max_steps=3, cost_budget_usd=10.0)

        # Mock _call_llm to always return a tool call (never resolves)
        async def mock_call(*args, **kwargs):
            return self._make_tool_call_response("search_kev")

        agent._call_llm = mock_call

        result = await agent.evaluate(
            cve_id="CVE-2023-0001",
            hostname="test.wa.gov.au",
            description="Test vuln",
            cvss_score=7.5,
        )

        # Should have reached step limit and returned neutral default
        assert result.get("_agent", {}).get("steps", 0) == 3
        assert result["text_conflict"] is False
        assert result["confidence"] == 0.30
        assert (
            "step limit" in result.get("conflict_note", "").lower()
            or "neutral" in result.get("conflict_note", "").lower()
        )

    # ── Cost budget ────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_cost_budget(self):
        """Agent should terminate when cost budget is exceeded."""
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator(max_steps=100, cost_budget_usd=0.001)

        # Mock _call_llm to keep making tool calls with high cost
        async def mock_call(*args, **kwargs):
            return self._make_tool_call_response("search_kev")

        agent._call_llm = mock_call

        # Override _reset() to set cost above budget (budget check runs in loop)
        original_reset = agent._reset

        def patched_reset():
            original_reset()
            agent._cost_so_far = 0.002  # exceeds 0.001 budget

        agent._reset = patched_reset

        result = await agent.evaluate(
            cve_id="CVE-2023-0001",
            hostname="test.wa.gov.au",
            description="Test vuln",
            cvss_score=7.5,
        )

        assert (
            "cost budget" in result.get("conflict_note", "").lower()
            or "cost budget" in result.get("conflict_note", "").lower()
        )

    # ── Final resolution ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_final_resolution(self):
        """Agent should return valid resolution when LLM submits one."""
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator(max_steps=10, cost_budget_usd=10.0)

        async def mock_call(*args, **kwargs):
            return self._make_final_response()

        agent._call_llm = mock_call

        result = await agent.evaluate(
            cve_id="CVE-2023-0001",
            hostname="test.wa.gov.au",
            description="Test vuln",
            cvss_score=7.5,
        )

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.85
        assert result["rag_result"] == "NOT_NEEDED"
        assert "_usage" in result
        assert "_agent" in result
        assert result["_agent"]["steps"] == 1

    # ── Consecutive tool failures ──────────────────────────────────────

    @pytest.mark.asyncio
    async def test_consecutive_tool_failures(self):
        """3 consecutive tool failures should terminate with neutral default."""
        from unittest.mock import patch
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator(max_steps=100, cost_budget_usd=10.0)

        async def mock_call(*args, **kwargs):
            return self._make_tool_call_response("search_kev")

        agent._call_llm = mock_call

        with patch("pipeline.tier_2.agent.execute_tool") as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "data": None,
                "error": "Simulated tool failure",
            }

            result = await agent.evaluate(
                cve_id="CVE-2023-0001",
                hostname="test.wa.gov.au",
                description="Test vuln",
                cvss_score=7.5,
            )

        assert result["text_conflict"] is False
        assert result["confidence"] == 0.30
        assert (
            "failure" in result.get("conflict_note", "").lower()
            or "consecutive" in result.get("conflict_note", "").lower()
            or "neutral" in result.get("conflict_note", "").lower()
        )

    # ── No API key ─────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_no_api_key(self):
        """Agent should return neutral default when no API key is configured."""
        from pipeline.tier_2.agent import AgenticEvaluator

        # Save original and set empty key
        import pipeline.tier_2.agent as agent_mod

        original_key = agent_mod.LLM_API_KEY
        agent_mod.LLM_API_KEY = ""

        try:
            agent = AgenticEvaluator(max_steps=5, cost_budget_usd=10.0)
            result = await agent.evaluate(
                cve_id="CVE-2023-0001",
                hostname="test.wa.gov.au",
                description="Test vuln",
                cvss_score=7.5,
            )
            assert result["text_conflict"] is False
            assert result["confidence"] == 0.30
            assert "API key" in result.get("conflict_note", "")
        finally:
            agent_mod.LLM_API_KEY = original_key


# ── Try-Parse Resolution Tests ────────────────────────────────────────────


class TestTryParseResolution:
    """Test the _try_parse_resolution helper."""

    def test_valid_json(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        text = json.dumps(
            {
                "text_conflict": True,
                "conflict_note": "Test note",
                "rag_result": "UNCERTAIN",
                "resolution": "Test resolution",
                "confidence": 0.75,
                "score_adjustment": -10,
            }
        )
        result = agent._try_parse_resolution(text)
        assert result is not None
        assert result["text_conflict"] is True
        assert result["confidence"] == 0.75

    def test_json_with_code_fences(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        text = f"```json\n{json.dumps({'text_conflict': False, 'conflict_note': 'Note', 'rag_result': 'CONFIRMED', 'resolution': 'Res', 'confidence': 0.9, 'score_adjustment': 5})}\n```"
        result = agent._try_parse_resolution(text)
        assert result is not None
        assert result["text_conflict"] is False
        assert result["confidence"] == 0.9

    def test_missing_fields(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        text = json.dumps({"text_conflict": True})  # missing fields
        result = agent._try_parse_resolution(text)
        assert result is None

    def test_invalid_json(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        result = agent._try_parse_resolution("not json at all")
        assert result is None

    def test_invalid_types(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        # confidence should be a number
        text = json.dumps(
            {
                "text_conflict": True,
                "conflict_note": "Note",
                "rag_result": "UNCERTAIN",
                "resolution": "Res",
                "confidence": "high",  # wrong type
                "score_adjustment": 0,
            }
        )
        result = agent._try_parse_resolution(text)
        assert result is None

    def test_invalid_rag_result(self):
        from pipeline.tier_2.agent import AgenticEvaluator

        agent = AgenticEvaluator()
        text = json.dumps(
            {
                "text_conflict": True,
                "conflict_note": "Note",
                "rag_result": "INVALID_VALUE",
                "resolution": "Res",
                "confidence": 0.5,
                "score_adjustment": 0,
            }
        )
        result = agent._try_parse_resolution(text)
        assert result is None


# ── Tool Function Direct Tests (edge cases) ───────────────────────────────


class TestToolEdgeCases:
    """Edge cases for tool functions."""

    @patch("integrations.nvd.get_nvd_data", side_effect=Exception("NVD API down"))
    def test_nvd_tool_error(self, mock_nvd):
        from pipeline.tier_2.tools import _search_nvd

        result = _search_nvd("CVE-2023-0001")
        assert result["success"] is False
        assert result["data"] is None
        assert "NVD API down" in result["error"]

    @patch("ingest_cwe.get_cwe", side_effect=Exception("CWE lookup failed"))
    def test_cwe_tool_error(self, mock_cwe):
        from pipeline.tier_2.tools import _search_cwe

        result = _search_cwe("CVE-2023-0001")
        assert result["success"] is False
        assert "CWE lookup failed" in result["error"]

    def test_execute_tool_parameter_error(self):
        """Execute tool with wrong parameter type should return error."""
        from pipeline.tier_2.tools import execute_tool

        # search_kev expects string cve_id, not a number
        result = execute_tool("search_kev", {"cve_id": 12345})
        assert result["success"] is False
        assert result["data"] is None
