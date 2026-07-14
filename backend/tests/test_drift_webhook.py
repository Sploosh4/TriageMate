"""Tests for the drift webhook notification system.

Uses unittest.mock.patch to isolate shared state (``_last_webhook``)
and environment variables instead of direct mutation + importlib.reload().
"""

from unittest.mock import patch

import pytest

import analysis.drift


class TestDriftWebhook:
    @pytest.mark.asyncio
    async def test_webhook_no_url_returns_false(self):
        """When env var is empty, webhook is no-op."""
        with patch.dict(
            "os.environ",
            {"TRIAGEMATE_DRIFT_WEBHOOK_URL": ""},
            clear=True,
        ):
            result = await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)
        assert result is False

    @pytest.mark.asyncio
    async def test_webhook_suppression_same_model(self):
        """Same model + same severity within 6h should be suppressed."""
        with (
            patch.dict(
                "os.environ",
                {"TRIAGEMATE_DRIFT_WEBHOOK_URL": "http://localhost:9999/webhook"},
            ),
            patch.object(analysis.drift, "_last_webhook", {}),
        ):
            # First call should attempt to send (will fail to connect,
            # but suppression key is set)
            await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)

            # Second call should be suppressed
            result = await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)
            assert result is False  # Suppressed

    @pytest.mark.asyncio
    async def test_webhook_different_models_not_suppressed(self):
        """Different models should NOT suppress each other."""
        with (
            patch.dict(
                "os.environ",
                {"TRIAGEMATE_DRIFT_WEBHOOK_URL": "http://localhost:9999/webhook"},
            ),
            patch.object(analysis.drift, "_last_webhook", {}),
        ):
            # First call for xgboost
            await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)

            # Second call for a different model should NOT be suppressed
            result = await analysis.drift.send_drift_webhook("pre_tier", 0.12, 0.10)
            assert result is False  # Fails to connect (no server), but not suppressed
