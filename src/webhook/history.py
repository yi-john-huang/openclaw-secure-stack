"""Per-session conversation history store for webhook relay.

Maintains multi-turn message history keyed by session_id, enabling
stateful conversations through a stateless upstream API.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

_DEFAULT_MAX_TURNS = 20  # user+assistant pairs
_DEFAULT_SESSION_TTL_SECONDS = 24 * 3600  # 24 hours


class ConversationHistory:
    """In-memory conversation history store keyed by session_id.

    Each entry is an OpenAI-compatible messages list:
        [{"role": "user"|"assistant", "content": str}, ...]

    Oldest messages are dropped when the history exceeds max_turns pairs.
    Sessions with no activity for longer than session_ttl_seconds are evicted
    to prevent unbounded memory growth from sender churn.
    """

    def __init__(
        self,
        max_turns: int = _DEFAULT_MAX_TURNS,
        session_ttl_seconds: float = _DEFAULT_SESSION_TTL_SECONDS,
    ) -> None:
        self._max_messages = max_turns * 2  # each turn = user + assistant
        self._session_ttl = session_ttl_seconds
        self._store: dict[str, list[dict[str, str]]] = {}
        self._last_seen: dict[str, float] = {}

    def get(self, session_id: str) -> list[dict[str, str]]:
        """Return a copy of the history for the given session."""
        return list(self._store.get(session_id, []))

    def append_user(self, session_id: str, content: str) -> None:
        """Append a user message, evict stale sessions, and truncate if over the limit."""
        self._evict_stale_sessions()
        history = self._store.setdefault(session_id, [])
        history.append({"role": "user", "content": content})
        self._last_seen[session_id] = time.monotonic()
        self._truncate(session_id)

    def append_assistant(self, session_id: str, content: str) -> None:
        """Append an assistant message and truncate if over the limit."""
        history = self._store.setdefault(session_id, [])
        history.append({"role": "assistant", "content": content})
        self._last_seen[session_id] = time.monotonic()
        self._truncate(session_id)

    def clear(self, session_id: str) -> None:
        """Remove all history for the given session."""
        self._store.pop(session_id, None)
        self._last_seen.pop(session_id, None)

    def _truncate(self, session_id: str) -> None:
        history = self._store[session_id]
        if len(history) > self._max_messages:
            dropped = len(history) - self._max_messages
            self._store[session_id] = history[-self._max_messages :]
            logger.debug(
                "Truncated conversation history for %s: dropped %d oldest messages",
                session_id,
                dropped,
            )

    def _evict_stale_sessions(self) -> None:
        now = time.monotonic()
        stale = [
            sid for sid, ts in self._last_seen.items()
            if now - ts > self._session_ttl
        ]
        for sid in stale:
            self._store.pop(sid, None)
            self._last_seen.pop(sid, None)
            logger.debug("Evicted stale conversation session: %s", sid)
