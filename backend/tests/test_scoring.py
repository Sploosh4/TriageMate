"""
Tests for the Scoring Engine (``scoring.py``).

``calculate_final_score`` is a pure function that combines seven weighted
dimensions (CVSS, EPSS, Asset Criticality, Exposure, Patch, ML Exploitation, Security Context)
into a 0-100 priority score with band mapping.

All tests are synchronous unit tests — no fixtures, no API client needed.
"""

from scoring import calculate_final_score

# ======================================================================
# Core Sanity Tests
# ======================================================================


class TestScoringSanity:
    """Basic sanity and boundary tests for the scoring engine."""

    def test_default_inputs_returns_reasonable_score(self):
        """Call with moderate inputs: verify score 0-100 int, band is valid."""
        result = calculate_final_score(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        assert isinstance(result["total"], int), (
            f"Expected int total, got {type(result['total'])}"
        )
        assert 0 <= result["total"] <= 100, (
            f"Score {result['total']} out of 0-100 range"
        )
        assert result["band"] in ("Low", "Medium", "Critical", "Very Critical"), (
            f"Unexpected band: {result['band']}"
        )
        assert "dimensions" in result
        assert len(result["dimensions"]) == 7

    def test_critical_cve_returns_very_high_score(self):
        """CVSS 10, EPSS 0.9, max criticality, internet-facing, no patch.
        Expect score > 80 and band 'Very Critical'."""
        result = calculate_final_score(
            cvss_score=10,
            epss_score=0.9,
            mission_prevalence="Core",
            public_wellbeing="Severe",
            data_classification="OFFICIAL Sensitive",
            internet_facing=True,
            patch_available=False,
            patch_applied=False,
        )
        assert result["total"] > 80, (
            f"Expected score > 80 for critical CVE, got {result['total']}"
        )
        assert result["band"] == "Very Critical", (
            f"Expected 'Very Critical', got '{result['band']}'"
        )

    def test_trivial_cve_returns_low_score(self):
        """CVSS 1, EPSS 0.01, minimal everything, patch applied.
        Expect score < 20 and band 'Low'."""
        result = calculate_final_score(
            cvss_score=1,
            epss_score=0.01,
            mission_prevalence="Peripheral",
            public_wellbeing="Minimal",
            data_classification="UNOFFICIAL",
            internet_facing=False,
            patch_available=True,
            patch_applied=True,
        )
        assert result["total"] < 20, (
            f"Expected score < 20 for trivial CVE, got {result['total']}"
        )
        assert result["band"] == "Low", f"Expected 'Low', got '{result['band']}'"


# ======================================================================
# Dimension Weight Tests
# ======================================================================


class TestDimensionWeights:
    """Each dimension should correctly influence the final score."""

    def test_mission_prevalence_weights_correctly(self):
        """Same CVSS/EPSS, Core must score higher than Peripheral."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        core = calculate_final_score(mission_prevalence="Core", **base)
        peripheral = calculate_final_score(mission_prevalence="Peripheral", **base)
        assert core["total"] > peripheral["total"], (
            f"Core ({core['total']}) should score > Peripheral ({peripheral['total']})"
        )

    def test_public_wellbeing_weights_correctly(self):
        """Same inputs, Severe wellbeing must score higher than Minimal."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        severe = calculate_final_score(public_wellbeing="Severe", **base)
        minimal = calculate_final_score(public_wellbeing="Minimal", **base)
        assert severe["total"] > minimal["total"], (
            f"Severe ({severe['total']}) should score > Minimal ({minimal['total']})"
        )

    def test_internet_facing_penalty(self):
        """Same inputs, internet_facing=True must score higher than False."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
        )
        facing = calculate_final_score(internet_facing=True, **base)
        not_facing = calculate_final_score(internet_facing=False, **base)
        assert facing["total"] > not_facing["total"], (
            f"Internet-facing ({facing['total']}) should score > "
            f"non-facing ({not_facing['total']})"
        )

    def test_patch_available_affects_score(self):
        """Compare patch_available=True (applied) vs no patch.
        Applied patch adds +5, making score higher."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        patched = calculate_final_score(
            patch_available=True, patch_applied=True, **base
        )
        no_patch = calculate_final_score(patch_available=False, **base)
        # Having a patch applied adds +5 to the total per current logic
        assert patched["total"] > no_patch["total"], (
            f"Applied patch ({patched['total']}) should score > "
            f"no patch ({no_patch['total']})"
        )

    def test_patch_applied_affects_score(self):
        """patch_applied=True must produce a different score than False."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
            patch_available=True,
        )
        applied = calculate_final_score(patch_applied=True, **base)
        not_applied = calculate_final_score(patch_applied=False, **base)
        # Applied adds +5 to the total; not applied adds 0
        assert applied["total"] > not_applied["total"], (
            f"Applied ({applied['total']}) should score > "
            f"not applied ({not_applied['total']})"
        )
        assert applied["dimensions"]["patch"] == 5, (
            f"Expected patch dimension=5, got {applied['dimensions']['patch']}"
        )
        assert not_applied["dimensions"]["patch"] == 0, (
            f"Expected patch dimension=0, got {not_applied['dimensions']['patch']}"
        )


# ======================================================================
# Pipeline Integration Tests
# ======================================================================


class TestPipelineIntegration:
    """Tests for Tier 2 adjustment and EPSS substitution."""

    def test_tier_2_adjustment_applied(self):
        """Pass tier_2_result with score_adjustment=10. Verify score increases."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        with_adjustment = calculate_final_score(
            tier_2_result={"score_adjustment": 10}, **base
        )
        without_adjustment = calculate_final_score(**base)
        assert with_adjustment["total"] == without_adjustment["total"] + 10, (
            f"Expected +10 adjustment: {without_adjustment['total']} + 10 = "
            f"{with_adjustment['total']}"
        )

    def test_tier_2_adjustment_clamps_at_20(self):
        """Verify score_adjustment over 20 is clamped to 20."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        with_adjustment = calculate_final_score(
            tier_2_result={"score_adjustment": 99}, **base
        )
        without_adjustment = calculate_final_score(**base)
        assert with_adjustment["total"] == without_adjustment["total"] + 20, (
            f"Expected +20 clamped adjustment, got {with_adjustment['total']}"
        )

    def test_substituted_epss_used(self):
        """Pass substituted_epss=0.8 with low epss=0.01.
        Score must be higher than without substitution."""
        base = dict(
            cvss_score=5,
            epss_score=0.01,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        with_sub = calculate_final_score(substituted_epss=0.8, **base)
        without_sub = calculate_final_score(**base)
        assert with_sub["total"] > without_sub["total"], (
            f"With substituted EPSS ({with_sub['total']}) should score > "
            f"without ({without_sub['total']})"
        )
        # The EPSS dimension should reflect the substituted value
        assert with_sub["dimensions"]["epss"] > without_sub["dimensions"]["epss"], (
            f"EPSS dimension with sub ({with_sub['dimensions']['epss']}) should be > "
            f"without sub ({without_sub['dimensions']['epss']})"
        )


# ======================================================================
# Band & Boundary Tests
# ======================================================================


class TestBandsAndBoundaries:
    """Band mapping and score clamping boundary tests."""

    def test_band_mapping_all_levels(self):
        """Verify all 4 bands can be reached by varying inputs."""

        # Low (total ≤ 25)
        low = calculate_final_score(
            cvss_score=1,
            epss_score=0.01,
            mission_prevalence="Peripheral",
            public_wellbeing="Minimal",
            data_classification="UNOFFICIAL",
            internet_facing=False,
            patch_available=True,
            patch_applied=True,
        )
        assert low["band"] == "Low", (
            f"Expected 'Low', got '{low['band']}' (total={low['total']})"
        )

        # Medium (26 ≤ total ≤ 50)
        medium = calculate_final_score(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        assert medium["band"] == "Medium", (
            f"Expected 'Medium', got '{medium['band']}' (total={medium['total']})"
        )

        # Critical (51 ≤ total ≤ 75)
        critical = calculate_final_score(
            cvss_score=8,
            epss_score=0.5,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=True,
        )
        assert critical["band"] == "Critical", (
            f"Expected 'Critical', got '{critical['band']}' (total={critical['total']})"
        )

        # Very Critical (total > 75)
        very_critical = calculate_final_score(
            cvss_score=10,
            epss_score=0.9,
            mission_prevalence="Core",
            public_wellbeing="Severe",
            data_classification="OFFICIAL Sensitive",
            internet_facing=True,
            patch_available=False,
        )
        assert very_critical["band"] == "Very Critical", (
            f"Expected 'Very Critical', got '{very_critical['band']}' "
            f"(total={very_critical['total']})"
        )

        # Verify they are all distinct bands
        bands = {low["band"], medium["band"], critical["band"], very_critical["band"]}
        assert bands == {"Low", "Medium", "Critical", "Very Critical"}, (
            f"Not all 4 bands produced: {bands}"
        )

    def test_score_clamps_to_0_100(self):
        """Verify extreme inputs don't push score below 0 or above 100."""

        # Minimal possible inputs
        min_result = calculate_final_score(
            cvss_score=0,
            epss_score=0.0,
            mission_prevalence="Peripheral",
            public_wellbeing="Minimal",
            data_classification="UNOFFICIAL",
            internet_facing=False,
            patch_available=False,
            tier_2_result={"score_adjustment": -99},
        )
        assert min_result["total"] >= 0, (
            f"Expected score >= 0, got {min_result['total']}"
        )

        # Maximum possible inputs (with tier 2 boost)
        max_result = calculate_final_score(
            cvss_score=10,
            epss_score=0.99,
            mission_prevalence="Core",
            public_wellbeing="Severe",
            data_classification="OFFICIAL Sensitive",
            internet_facing=True,
            patch_available=True,
            patch_applied=True,
            tier_2_result={"score_adjustment": 99},
        )
        assert max_result["total"] <= 100, (
            f"Expected score <= 100, got {max_result['total']}"
        )
        # With max inputs and clamped tier 2, it should hit exactly 100
        assert max_result["total"] == 100, (
            f"Expected score to clamp at 100, got {max_result['total']}"
        )


# ======================================================================
# Edge Case Tests
# ======================================================================


class TestEdgeCases:
    """Edge cases for non-standard inputs."""

    def test_tier_2_empty_result_does_not_crash(self):
        """Passing an empty tier_2_result dict should not affect score."""
        base = dict(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        result_empty = calculate_final_score(tier_2_result={}, **base)
        result_none = calculate_final_score(tier_2_result=None, **base)
        result_base = calculate_final_score(**base)
        assert result_empty["total"] == result_base["total"], (
            f"Empty tier_2 should not change score: {result_empty['total']} vs "
            f"{result_base['total']}"
        )
        assert result_none["total"] == result_base["total"], (
            f"None tier_2 should not change score: {result_none['total']} vs "
            f"{result_base['total']}"
        )

    def test_ml_exploitation_dimension_zero_when_no_tier_1(self):
        """Without tier_1_result, ml_exploitation dimension should be 0."""
        result = calculate_final_score(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
        )
        assert result["dimensions"]["ml_exploitation"] == 0, (
            f"Expected ml_exploitation=0, got {result['dimensions']['ml_exploitation']}"
        )

    def test_tier_1_exploitation_probability_reflected(self):
        """Pass tier_1_result with exploitation_probability, verify dimension."""
        result = calculate_final_score(
            cvss_score=5,
            epss_score=0.05,
            mission_prevalence="Core",
            public_wellbeing="Moderate",
            data_classification="OFFICIAL",
            internet_facing=False,
            tier_1_result={"exploitation_probability": 0.85},
        )
        assert result["dimensions"]["ml_exploitation"] == 9, (
            f"Expected ml_exploitation=9 (0.85*10=8.5→9), "
            f"got {result['dimensions']['ml_exploitation']}"
        )
