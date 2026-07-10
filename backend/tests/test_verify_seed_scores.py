"""
Tests for the Seed Data Score Verification script (``scripts.verify_seed_scores``).

Uses ``unittest.mock.patch`` to override ``calculate_final_score`` and
test both pass and fail scenarios without requiring real scoring logic.
"""

from unittest.mock import patch

from scripts.verify_seed_scores import verify_seed_scores


class TestVerifySeedScores:
    """Tests for verify_seed_scores() with mocked scoring."""

    def test_verify_seed_scores_passes_when_correct(self):
        """When calculated scores match the canonical contract, all_pass=True."""
        # Mock calculate_final_score to return values matching canonical baseline
        canonical = [94, 92, 76, 86, 78, 91, 77]
        cve_order = [
            "CVE-2023-34362",
            "CVE-2023-4966",
            "CVE-2023-27350",
            "CVE-2024-1709",
            "CVE-2023-36884",
            "CVE-2023-22515",
            "CVE-2022-47966",
        ]
        # Mock run_pipeline_and_get_scores directly
        with patch(
            "scripts.verify_seed_scores.run_pipeline_and_get_scores"
        ) as mock_run:
            mock_run.return_value = dict(zip(cve_order, canonical))
            result = verify_seed_scores()
            assert result["all_pass"] is True, (
                f"Expected all_pass=True, got {result['all_pass']}"
            )
            for cve_id in cve_order:
                assert result["results"][cve_id]["pass"] is True, (
                    f"CVE {cve_id} should pass, got {result['results'][cve_id]}"
                )

    def test_verify_seed_scores_detects_drift(self):
        """When calculated scores diverge from canonical, all_pass=False."""
        canonical = [94, 92, 76, 86, 78, 91, 77]
        cve_order = [
            "CVE-2023-34362",
            "CVE-2023-4966",
            "CVE-2023-27350",
            "CVE-2024-1709",
            "CVE-2023-36884",
            "CVE-2023-22515",
            "CVE-2022-47966",
        ]
        # Return scores that are +10 from canonical
        drifted = {cve: score + 10 for cve, score in zip(cve_order, canonical)}

        with patch(
            "scripts.verify_seed_scores.run_pipeline_and_get_scores"
        ) as mock_run:
            mock_run.return_value = drifted
            result = verify_seed_scores()

            assert result["all_pass"] is False, (
                f"Expected all_pass=False for drifted scores, got {result['all_pass']}"
            )
            # All should fail since drift > tolerance
            for cve_id in cve_order:
                assert result["results"][cve_id]["pass"] is False, (
                    f"CVE {cve_id} should fail with +10 drift, "
                    f"got {result['results'][cve_id]}"
                )

    def test_verify_seed_scores_partial_drift(self):
        """Only drifted CVEs fail; matching CVEs still pass."""
        canonical = [94, 92, 76, 86, 78, 91, 77]
        cve_order = [
            "CVE-2023-34362",
            "CVE-2023-4966",
            "CVE-2023-27350",
            "CVE-2024-1709",
            "CVE-2023-36884",
            "CVE-2023-22515",
            "CVE-2022-47966",
        ]
        # Only the first CVE drifts
        scores = dict(zip(cve_order, canonical))
        scores["CVE-2023-34362"] += 10  # Drift this one

        with patch(
            "scripts.verify_seed_scores.run_pipeline_and_get_scores"
        ) as mock_run:
            mock_run.return_value = scores
            result = verify_seed_scores()

            assert result["all_pass"] is False, (
                f"Expected all_pass=False with partial drift, got {result['all_pass']}"
            )
            assert result["results"]["CVE-2023-34362"]["pass"] is False, (
                "CVE-2023-34362 should fail"
            )
            # All others should still pass
            for cve_id in cve_order[1:]:
                assert result["results"][cve_id]["pass"] is True, (
                    f"CVE {cve_id} should pass, got {result['results'][cve_id]}"
                )

    def test_verify_seed_scores_returns_expected_keys(self):
        """Result dict has expected structure."""
        with patch(
            "scripts.verify_seed_scores.run_pipeline_and_get_scores"
        ) as mock_run:
            mock_run.return_value = {
                "CVE-2023-34362": 94,
                "CVE-2023-4966": 92,
                "CVE-2023-27350": 76,
                "CVE-2024-1709": 86,
                "CVE-2023-36884": 78,
                "CVE-2023-22515": 91,
                "CVE-2022-47966": 77,
            }
            result = verify_seed_scores()

            assert "results" in result, "Missing 'results' key"
            assert "all_pass" in result, "Missing 'all_pass' key"
            assert isinstance(result["results"], dict), (
                f"results should be dict, got {type(result['results'])}"
            )
            assert isinstance(result["all_pass"], bool), (
                f"all_pass should be bool, got {type(result['all_pass'])}"
            )

            # Check per-CVE entry structure
            for cve_id, entry in result["results"].items():
                assert "expected" in entry, f"{cve_id} missing 'expected'"
                assert "actual" in entry, f"{cve_id} missing 'actual'"
                assert "delta" in entry, f"{cve_id} missing 'delta'"
                assert "pass" in entry, f"{cve_id} missing 'pass'"
                assert isinstance(entry["expected"], int), (
                    f"{cve_id} expected should be int"
                )
                assert isinstance(entry["actual"], int), (
                    f"{cve_id} actual should be int"
                )
                assert isinstance(entry["delta"], (int, float)), (
                    f"{cve_id} delta should be numeric, got {type(entry['delta'])}"
                )
                assert isinstance(entry["pass"], bool), f"{cve_id} pass should be bool"
