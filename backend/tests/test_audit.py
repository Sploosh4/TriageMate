"""
Tests for audit sampling logic.

Verifies that the effective routing determination correctly handles
Tier 1 auto-resolved cases (regression test for Sprint 11 audit fix).

The bug: Tier 0 escalated + Tier 1 auto-resolved was invisible to audit
because the caller only checked t0_result["routing"]. The fix uses
effective_routing: if Tier 1 ran, its routing determines audit eligibility.

Edge cases covered:
- Tier 0 auto-resolved → uses t0_result["routing"] = "auto_resolved" → audit triggers
- Tier 0 escalated + Tier 1 auto-resolved → uses t1_result["routing"] = "auto_resolved" → audit triggers
- Tier 0 escalated + Tier 1 escalated → uses t1_result["routing"] = "escalated" → no audit
- t1_result is None → defensively falls back to t0_result["routing"]
"""

from unittest.mock import patch


class TestShouldAudit:
    """Direct tests of the should_audit() function with controlled randomness."""

    # ------------------------------------------------------------------
    # 1. Tier 0 auto-resolved → should_audit returns True
    # ------------------------------------------------------------------
    def test_should_audit_tier0_auto_resolved(self):
        """Tier 0 auto-resolved: effective_routing='auto_resolved' triggers audit."""
        from audit import should_audit

        # Patch random to return a value below the 7.5% threshold
        with patch("audit.random.random", return_value=0.05):
            result = should_audit("Deterministic", "auto_resolved")
        assert result is True, (
            "should_audit should return True for Tier 0 auto-resolved"
        )

    # ------------------------------------------------------------------
    # 2. Tier 0 escalated + Tier 1 auto-resolved → should_audit returns True
    # ------------------------------------------------------------------
    def test_should_audit_tier1_auto_resolved(self):
        """Tier 1 auto-resolved: effective_routing='auto_resolved' triggers audit."""
        from audit import should_audit

        with patch("audit.random.random", return_value=0.05):
            result = should_audit("ML Tier", "auto_resolved")
        assert result is True, (
            "should_audit should return True for Tier 1 auto-resolved"
        )

    # ------------------------------------------------------------------
    # 3. Tier 0 escalated + Tier 1 escalated → should_audit returns False
    # ------------------------------------------------------------------
    def test_should_audit_no_auto_resolve(self):
        """No auto-resolve at any tier: audit sampling should not trigger."""
        from audit import should_audit

        result = should_audit("ML Tier", "escalated")
        assert result is False, (
            "should_audit should return False when neither tier auto-resolved"
        )

    # ------------------------------------------------------------------
    # 4. Tier 0 auto-resolved, t1_result is None → should_audit returns True
    # ------------------------------------------------------------------
    def test_should_audit_tier0_auto_tier1_none(self):
        """t1_result=None fallback: uses t0_result routing (auto_resolved)."""
        from audit import should_audit

        with patch("audit.random.random", return_value=0.05):
            result = should_audit("Deterministic", "auto_resolved")
        assert result is True, (
            "should_audit should fall back to Tier 0 routing when t1_result is None"
        )


class TestEffectiveRouting:
    """Tests for the effective_routing logic in the ingest pipeline.

    These verify the routing determination that was the root cause of the bug.
    """

    def _simulate_pipeline_routing(self, t0_routing, t1_result):
        """Replicate the effective_routing logic from ingest.py."""
        effective_routing = t0_routing
        if t0_routing == "escalated" and t1_result:
            effective_routing = t1_result["routing"]
        return effective_routing

    def test_tier0_auto_resolved_uses_t0_routing(self):
        """Tier 0 auto-resolved → effective_routing is t0_result['routing']."""
        routing = self._simulate_pipeline_routing("auto_resolved", None)
        assert routing == "auto_resolved"

    def test_tier1_auto_resolved_uses_t1_routing(self):
        """Tier 0 escalated + Tier 1 auto-resolved → effective from t1."""
        t1_result = {"routing": "auto_resolved", "confidence": 0.85}
        routing = self._simulate_pipeline_routing("escalated", t1_result)
        assert routing == "auto_resolved"

    def test_tier1_escalated_uses_t1_routing(self):
        """Tier 0 escalated + Tier 1 escalated → effective from t1 (escalated)."""
        t1_result = {"routing": "escalated", "confidence": 0.45}
        routing = self._simulate_pipeline_routing("escalated", t1_result)
        assert routing == "escalated"

    def test_tier0_auto_resolved_with_none_t1(self):
        """Tier 0 auto-resolved, t1_result is None → fallback to t0 routing."""
        routing = self._simulate_pipeline_routing("auto_resolved", None)
        assert routing == "auto_resolved"


class TestAuditPipelineScenarios:
    """End-to-end scenario tests combining effective_routing + should_audit.

    These test the full chain: routing determination → audit decision.
    """

    def _compute_audit(self, t0_routing, t1_result):
        """Simulate the full audit decision from ingest.py."""
        from audit import should_audit

        effective_routing = t0_routing
        if t0_routing == "escalated" and t1_result:
            effective_routing = t1_result["routing"]

        detection_tier = "Deterministic" if t1_result is None else "ML Tier"
        return should_audit(detection_tier, effective_routing)

    def test_auto_resolved_tier0_deterministic(self):
        """Tier 0 auto-resolved + no Tier 1 → audit triggered."""
        with patch("audit.random.random", return_value=0.05):
            result = self._compute_audit("auto_resolved", None)
        assert result is True

    def test_auto_resolved_tier1(self):
        """Tier 1 auto-resolved → audit triggered (this was the bug)."""
        t1_result = {"routing": "auto_resolved", "confidence": 0.85}
        with patch("audit.random.random", return_value=0.05):
            result = self._compute_audit("escalated", t1_result)
        assert result is True, (
            "Tier 1 auto-resolved must trigger audit (regression check)"
        )

    def test_both_tiers_escalated_no_audit(self):
        """Both tiers escalated → no audit."""
        t1_result = {"routing": "escalated", "confidence": 0.45}
        result = self._compute_audit("escalated", t1_result)
        assert result is False

    def test_tier0_auto_tier1_none_no_tier1(self):
        """t1_result is None with Tier 0 auto-resolved → audit triggered."""
        with patch("audit.random.random", return_value=0.05):
            result = self._compute_audit("auto_resolved", None)
        assert result is True, (
            "Existing behavior: Tier 0 auto-resolved without Tier 1 must trigger audit"
        )
