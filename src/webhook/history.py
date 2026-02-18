"""Per-session conversation history store for webhook relay.

Maintains multi-turn message history keyed by sender_id, enabling
stateful conversations through a stateless upstream API.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_DEFAULT_MAX_TURNS = 20  # user+assistant pairs


class ConversationHistory:
    """In-memory conversation history store keyed by sender_id.

    Each entry is an OpenAI-compatible messages list:
        [{"role": "user"|"assistant", "content": str}, ...]

    Oldest messages are dropped when the history exceeds max_turns pairs,
    preserving the most recent context for the model.
    """

    def __init__(self, max_turns: int = _DEFAULT_MAX_TURNS) -> None:
        self._max_messages = max_turns * 2  # each turn = user + assistant
        self._store: dict[str, list[dict[str, str]]] = {}

    def get(self, session_id: str) -> list[dict[str, str]]:
        """Return a copy of the history for the given session."""
        return list(self._store.get(session_id, []))

    def append_user(self, session_id: str, content: str) -> None:
        """Append a user message and truncate if over the limit."""
        history = self._store.setdefault(session_id, [])
        history.append({"role": "user", "content": content})
        self._truncate(session_id)

    def append_assistant(self, session_id: str, content: str) -> None:
        """Append an assistant message and truncate if over the limit."""
        history = self._store.setdefault(session_id, [])
        history.append({"role": "assistant", "content": content})
        self._truncate(session_id)

    def clear(self, session_id: str) -> None:
        """Remove all history for the given session."""
        self._store.pop(session_id, None)

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
