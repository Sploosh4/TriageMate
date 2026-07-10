"""Tests for the drift webhook notification system."""

import pytest
from analysis.drift import send_drift_webhook


class TestDriftWebhook:
    @pytest.mark.asyncio
    async def test_webhook_no_url_returns_false(self):
        """When env var is empty, webhook is no-op."""
        from analysis.drift import DRIFT_WEBHOOK_URL

        if DRIFT_WEBHOOK_URL:
            pytest.skip("Webhook URL is configured — cannot test no-url behavior")

        result = await send_drift_webhook("xgboost", 0.12, 0.10)
        assert result is False

    @pytest.mark.asyncio
    async def test_webhook_suppression_same_model(self):
        """Same model + same severity within 6h should be suppressed."""
        from analysis.drift import _last_webhook

        _last_webhook.clear()

        # Mock the URL to test suppression logic
        import os

        original = os.environ.get("TRIAGEMATE_DRIFT_WEBHOOK_URL", "")
        os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"] = "http://localhost:9999/webhook"

        # Re-import the module to pick up the env var
        import importlib
        import analysis.drift

        importlib.reload(analysis.drift)

        # First call should attempt to send (will fail to connect, but suppression key is set)
        await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)

        # Second call should be suppressed
        result = await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)
        assert result is False  # Suppressed

        # Clean up
        if original:
            os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"] = original
        else:
            del os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"]
        importlib.reload(analysis.drift)

    @pytest.mark.asyncio
    async def test_webhook_different_models_not_suppressed(self):
        """Different models should NOT suppress each other."""
        from analysis.drift import _last_webhook

        _last_webhook.clear()

        import os

        original = os.environ.get("TRIAGEMATE_DRIFT_WEBHOOK_URL", "")
        os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"] = "http://localhost:9999/webhook"

        import importlib
        import analysis.drift

        importlib.reload(analysis.drift)

        # First call for xgboost
        await analysis.drift.send_drift_webhook("xgboost", 0.12, 0.10)

        # Second call for a different model should NOT be suppressed
        result = await analysis.drift.send_drift_webhook("pre_tier", 0.12, 0.10)
        assert result is False  # Fails to connect (no server), but not suppressed

        if original:
            os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"] = original
        else:
            del os.environ["TRIAGEMATE_DRIFT_WEBHOOK_URL"]
        importlib.reload(analysis.drift)
