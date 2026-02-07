"""In-memory sliding window rate limiter for webhook endpoints — NFR-8, SEC-D-06."""

from __future__ import annotations

import time


class WebhookRateLimiter:
    """Sliding window rate limiter per source IP.

    Default: 60 requests per 60 seconds per IP.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._counters: dict[str, list[float]] = {}

    def check(self, source_ip: str) -> bool:
        """Return True if request is within rate limit for the given IP."""
        now = time.time()
        timestamps = self._counters.get(source_ip, [])
        # Prune entries outside the sliding window
        cutoff = now - self._window_seconds
        timestamps = [t for t in timestamps if t > cutoff]

        if not timestamps:
            self._counters.pop(source_ip, None)

        if len(timestamps) >= self._max_requests:
            self._counters[source_ip] = timestamps
            return False

        timestamps.append(now)
        self._counters[source_ip] = timestamps
        return True
