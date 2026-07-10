"""Tests for Tier 0 deterministic routing rules."""

from pipeline.config.thresholds import CWE_EPSS_THRESHOLDS
from pipeline import tier_0


class TestTier0NvdRefCount:
    def test_nvd_ref_count_above_threshold_auto_resolves_very_critical(self):
        """≥21 refs → auto_resolved very_critical."""
        result = tier_0.evaluate_tier_0(
            cvss_score=5.0,
            cisa_kev=False,
            epss_score=0.05,
            data_classification="OFFICIAL",
            internet_facing=False,
            nvd_reference_count=25,
        )
        assert result["routing"] == "auto_resolved"
        assert result["resolution"] == "very_critical"

    def test_nvd_ref_count_below_threshold_does_not_trigger(self):
        """<21 refs → rule does not fire, falls through."""
        result = tier_0.evaluate_tier_0(
            cvss_score=5.0,
            cisa_kev=False,
            epss_score=0.05,
            data_classification="OFFICIAL",
            internet_facing=False,
            nvd_reference_count=5,
        )
        # Falls through — not very_critical
        assert result["resolution"] != "very_critical"

    def test_nvd_ref_count_default_zero(self):
        """Default 0 should not trigger the rule."""
        result = tier_0.evaluate_tier_0(
            cvss_score=5.0,
            cisa_kev=False,
            epss_score=0.05,
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        assert result["resolution"] != "very_critical"

    def test_nvd_ref_count_at_threshold(self):
        """Exactly 21 should trigger."""
        result = tier_0.evaluate_tier_0(
            cvss_score=5.0,
            cisa_kev=False,
            epss_score=0.05,
            data_classification="OFFICIAL",
            internet_facing=False,
            nvd_reference_count=21,
        )
        assert result["routing"] == "auto_resolved"
        assert result["resolution"] == "very_critical"

    def test_nvd_ref_count_rule_plays_nicely_with_kev_rule(self):
        """Existing KEV rule should still work when NVD rule doesn't fire."""
        result = tier_0.evaluate_tier_0(
            cvss_score=9.5,
            cisa_kev=True,
            epss_score=0.95,
            data_classification="OFFICIAL Sensitive",
            internet_facing=True,
            nvd_reference_count=0,
        )
        assert result["routing"] == "auto_resolved"


class TestTier0CweStratifiedThresholds:
    def test_cwe_78_low_threshold_is_higher(self):
        """CWE-78 has threshold 0.515 — EPSS 0.30 should auto-resolve as low when not KEV."""
        threshold = CWE_EPSS_THRESHOLDS.get("CWE-78", 0.10)
        result = tier_0.evaluate_tier_0(
            cvss_score=3.0,
            cisa_kev=False,
            epss_score=threshold - 0.01,
            data_classification="OFFICIAL",
            internet_facing=False,
            cwe_class="CWE-78",
        )
        assert result["routing"] == "auto_resolved"
        assert result["resolution"] == "low"

    def test_cwe_22_low_threshold_is_lower(self):
        """CWE-22 has threshold 0.085 — EPSS 0.09 should escalate."""
        result = tier_0.evaluate_tier_0(
            cvss_score=3.0,
            cisa_kev=False,
            epss_score=0.09,
            data_classification="OFFICIAL",
            internet_facing=False,
            cwe_class="CWE-22",
        )
        # 0.09 > 0.085 (Path Traversal threshold) — should NOT auto-resolve as low
        assert result["routing"] != "auto_resolved" or result["resolution"] != "low"

    def test_default_cwe_uses_monolithic_threshold(self):
        """Unknown CWE falls back to 0.10 monolithic threshold."""
        result = tier_0.evaluate_tier_0(
            cvss_score=3.0,
            cisa_kev=False,
            epss_score=0.05,
            data_classification="OFFICIAL",
            internet_facing=False,
            cwe_class="CWE-9999",
        )
        assert result["routing"] == "auto_resolved"
        assert result["resolution"] == "low"

    def test_cwe_stratified_kev_threshold(self):
        """CWE-22 KEV uses threshold 0.085 instead of 0.90."""
        result = tier_0.evaluate_tier_0(
            cvss_score=5.0,
            cisa_kev=True,
            epss_score=0.10,
            data_classification="OFFICIAL Sensitive",
            internet_facing=False,
            cwe_class="CWE-22",
        )
        # 0.10 > 0.085 (CWE-22 threshold) — should auto-resolve very_critical
        assert result["routing"] == "auto_resolved"
        assert result["resolution"] == "very_critical"
