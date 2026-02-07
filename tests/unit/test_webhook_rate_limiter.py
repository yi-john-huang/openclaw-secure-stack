"""Tests for webhook rate limiter — NFR-8, SEC-D-06."""

from __future__ import annotations

from unittest.mock import patch

from src.webhook.rate_limiter import WebhookRateLimiter


class TestWebhookRateLimiter:
    """NFR-8: Webhook rate limiting — sliding window per source IP."""

    def test_allows_within_limit(self) -> None:
        limiter = WebhookRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check("192.168.1.1") is True

    def test_blocks_over_limit(self) -> None:
        limiter = WebhookRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            limiter.check("192.168.1.1")
        assert limiter.check("192.168.1.1") is False

    def test_different_ips_independent(self) -> None:
        limiter = WebhookRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.check("192.168.1.1") is True
        assert limiter.check("192.168.1.2") is True

    def test_window_expiry_resets_count(self) -> None:
        limiter = WebhookRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.check("192.168.1.1") is True
        assert limiter.check("192.168.1.1") is False
        # Simulate time passing beyond the window
        with patch("src.webhook.rate_limiter.time") as mock_time:
            mock_time.time.return_value = __import__("time").time() + 61
            assert limiter.check("192.168.1.1") is True

    def test_default_60_per_minute(self) -> None:
        limiter = WebhookRateLimiter()
        assert limiter._max_requests == 60
        assert limiter._window_seconds == 60

    def test_exactly_at_limit_allowed(self) -> None:
        limiter = WebhookRateLimiter(max_requests=3, window_seconds=60)
        assert limiter.check("10.0.0.1") is True
        assert limiter.check("10.0.0.1") is True
        assert limiter.check("10.0.0.1") is True
        # Next one over limit
        assert limiter.check("10.0.0.1") is False

    def test_stale_entries_pruned_on_check(self) -> None:
        """Old timestamps are removed during check, freeing capacity."""
        limiter = WebhookRateLimiter(max_requests=2, window_seconds=10)
        base_time = 1000.0
        with patch("src.webhook.rate_limiter.time") as mock_time:
            mock_time.time.return_value = base_time
            assert limiter.check("10.0.0.1") is True
            assert limiter.check("10.0.0.1") is True
            assert limiter.check("10.0.0.1") is False
            # Move time forward past the window
            mock_time.time.return_value = base_time + 11
            assert limiter.check("10.0.0.1") is True
