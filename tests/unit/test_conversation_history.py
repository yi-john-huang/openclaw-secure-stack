"""Tests for ConversationHistory — per-session multi-turn context store."""

from __future__ import annotations

import pytest

from src.webhook.history import ConversationHistory


class TestConversationHistory:
    def test_empty_session_returns_empty_list(self) -> None:
        history = ConversationHistory()
        assert history.get("user-1") == []

    def test_append_user_message(self) -> None:
        history = ConversationHistory()
        history.append_user("user-1", "hello")
        assert history.get("user-1") == [{"role": "user", "content": "hello"}]

    def test_append_assistant_message(self) -> None:
        history = ConversationHistory()
        history.append_user("user-1", "hello")
        history.append_assistant("user-1", "hi there")
        assert history.get("user-1") == [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi there"},
        ]

    def test_multiple_turns_accumulate(self) -> None:
        history = ConversationHistory()
        history.append_user("user-1", "turn 1")
        history.append_assistant("user-1", "reply 1")
        history.append_user("user-1", "turn 2")
        history.append_assistant("user-1", "reply 2")

        msgs = history.get("user-1")
        assert len(msgs) == 4
        assert msgs[2] == {"role": "user", "content": "turn 2"}
        assert msgs[3] == {"role": "assistant", "content": "reply 2"}

    def test_histories_are_isolated_by_session(self) -> None:
        history = ConversationHistory()
        history.append_user("alice", "alice msg")
        history.append_user("bob", "bob msg")

        assert history.get("alice") == [{"role": "user", "content": "alice msg"}]
        assert history.get("bob") == [{"role": "user", "content": "bob msg"}]

    def test_get_returns_copy_not_reference(self) -> None:
        """Mutating the returned list must not affect stored history."""
        history = ConversationHistory()
        history.append_user("user-1", "hello")
        snapshot = history.get("user-1")
        snapshot.append({"role": "user", "content": "injected"})

        assert len(history.get("user-1")) == 1

    def test_truncation_drops_oldest_messages(self) -> None:
        history = ConversationHistory(max_turns=2)  # max 4 messages
        for i in range(3):  # 3 turns = 6 messages → drop first 2
            history.append_user("user-1", f"user {i}")
            history.append_assistant("user-1", f"bot {i}")

        msgs = history.get("user-1")
        assert len(msgs) == 4
        # Oldest 2 messages (turn 0) should be gone
        assert msgs[0] == {"role": "user", "content": "user 1"}
        assert msgs[-1] == {"role": "assistant", "content": "bot 2"}

    def test_clear_removes_session(self) -> None:
        history = ConversationHistory()
        history.append_user("user-1", "hello")
        history.clear("user-1")
        assert history.get("user-1") == []

    def test_clear_nonexistent_session_is_safe(self) -> None:
        history = ConversationHistory()
        history.clear("does-not-exist")  # should not raise

    def test_stale_sessions_are_evicted(self) -> None:
        """P2: Sessions inactive beyond TTL are removed on next append_user."""
        import time

        history = ConversationHistory(session_ttl_seconds=0.01)  # 10ms TTL
        history.append_user("old-user", "hello")
        assert len(history.get("old-user")) == 1

        time.sleep(0.05)  # wait past TTL

        # Trigger eviction via a new session's append_user
        history.append_user("new-user", "hi")
        assert history.get("old-user") == []  # evicted
        assert len(history.get("new-user")) == 1  # new session intact

    def test_active_sessions_not_evicted(self) -> None:
        """Sessions within TTL are preserved."""
        history = ConversationHistory(session_ttl_seconds=60)
        history.append_user("active", "hello")
        history.append_user("trigger", "hi")  # triggers eviction scan
        assert len(history.get("active")) == 1  # still alive


class TestWebhookRelayWithHistory:
    """Integration: history wired into WebhookRelayPipeline."""

    @pytest.mark.asyncio
    async def test_history_builds_up_across_relays(self) -> None:
        """Second relay call sends both turns to upstream."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.webhook.history import ConversationHistory
        from src.webhook.models import WebhookMessage, WebhookResponse
        from src.webhook.relay import WebhookRelayPipeline

        sanitizer = MagicMock()
        sanitizer.sanitize.side_effect = lambda t: MagicMock(clean=t, injection_detected=False)
        history = ConversationHistory()
        pipeline = WebhookRelayPipeline(
            sanitizer=sanitizer,
            upstream_url="http://openclaw:3000",
            upstream_token="tok",
            conversation_history=history,
        )

        msg1 = WebhookMessage(source="telegram", text="hi", sender_id="u1", metadata={})
        msg2 = WebhookMessage(source="telegram", text="what time is it?", sender_id="u1", metadata={})

        with patch.object(pipeline, "_forward_to_upstream", new_callable=AsyncMock) as mock_fwd:
            mock_fwd.return_value = WebhookResponse(text="hello!", status_code=200)
            await pipeline.relay(msg1)

            mock_fwd.return_value = WebhookResponse(text="it is noon", status_code=200)
            await pipeline.relay(msg2)

        # The second upstream call receives: [user: hi, assistant: hello!, user: what time?]
        # (the assistant reply "it is noon" is appended AFTER the upstream call returns)
        sent_body: dict = mock_fwd.call_args[0][0]
        messages = sent_body["messages"]
        assert len(messages) == 3
        assert messages[0] == {"role": "user", "content": "hi"}
        assert messages[1] == {"role": "assistant", "content": "hello!"}
        assert messages[2] == {"role": "user", "content": "what time is it?"}

        # Full history after both turns has 4 messages, keyed by source:sender_id
        assert len(history.get("telegram:u1")) == 4

    @pytest.mark.asyncio
    async def test_history_not_updated_on_upstream_error(self) -> None:
        """Failed upstream response does not append assistant message."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.webhook.history import ConversationHistory
        from src.webhook.models import WebhookMessage, WebhookResponse
        from src.webhook.relay import WebhookRelayPipeline

        sanitizer = MagicMock()
        sanitizer.sanitize.side_effect = lambda t: MagicMock(clean=t, injection_detected=False)
        history = ConversationHistory()
        pipeline = WebhookRelayPipeline(
            sanitizer=sanitizer,
            upstream_url="http://openclaw:3000",
            upstream_token="tok",
            conversation_history=history,
        )

        msg = WebhookMessage(source="telegram", text="hello", sender_id="u1", metadata={})

        with patch.object(pipeline, "_forward_to_upstream", new_callable=AsyncMock) as mock_fwd:
            mock_fwd.return_value = WebhookResponse(text="Upstream unavailable", status_code=502)
            await pipeline.relay(msg)

        # Only the user message should be in history; no assistant reply
        msgs = history.get("telegram:u1")
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"

    @pytest.mark.asyncio
    async def test_sessions_isolated_across_senders(self) -> None:
        """Two different senders maintain independent histories."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.webhook.history import ConversationHistory
        from src.webhook.models import WebhookMessage, WebhookResponse
        from src.webhook.relay import WebhookRelayPipeline

        sanitizer = MagicMock()
        sanitizer.sanitize.side_effect = lambda t: MagicMock(clean=t, injection_detected=False)
        history = ConversationHistory()
        pipeline = WebhookRelayPipeline(
            sanitizer=sanitizer,
            upstream_url="http://openclaw:3000",
            upstream_token="tok",
            conversation_history=history,
        )

        alice = WebhookMessage(source="telegram", text="alice msg", sender_id="alice", metadata={})
        bob = WebhookMessage(source="telegram", text="bob msg", sender_id="bob", metadata={})

        with patch.object(pipeline, "_forward_to_upstream", new_callable=AsyncMock) as mock_fwd:
            mock_fwd.return_value = WebhookResponse(text="ok", status_code=200)
            await pipeline.relay(alice)
            await pipeline.relay(bob)

        assert history.get("telegram:alice") == [
            {"role": "user", "content": "alice msg"},
            {"role": "assistant", "content": "ok"},
        ]
        assert history.get("telegram:bob") == [
            {"role": "user", "content": "bob msg"},
            {"role": "assistant", "content": "ok"},
        ]

    @pytest.mark.asyncio
    async def test_same_id_different_channels_isolated(self) -> None:
        """P1: Same numeric ID on Telegram vs WhatsApp uses separate sessions."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.webhook.history import ConversationHistory
        from src.webhook.models import WebhookMessage, WebhookResponse
        from src.webhook.relay import WebhookRelayPipeline

        sanitizer = MagicMock()
        sanitizer.sanitize.side_effect = lambda t: MagicMock(clean=t, injection_detected=False)
        history = ConversationHistory()
        pipeline = WebhookRelayPipeline(
            sanitizer=sanitizer,
            upstream_url="http://openclaw:3000",
            upstream_token="tok",
            conversation_history=history,
        )

        tg_msg = WebhookMessage(source="telegram", text="from telegram", sender_id="12345", metadata={})
        wa_msg = WebhookMessage(source="whatsapp", text="from whatsapp", sender_id="12345", metadata={})

        with patch.object(pipeline, "_forward_to_upstream", new_callable=AsyncMock) as mock_fwd:
            mock_fwd.return_value = WebhookResponse(text="ok", status_code=200)
            await pipeline.relay(tg_msg)
            await pipeline.relay(wa_msg)

        tg_history = history.get("telegram:12345")
        wa_history = history.get("whatsapp:12345")
        assert len(tg_history) == 2  # user + assistant
        assert len(wa_history) == 2  # user + assistant
        assert tg_history[0]["content"] == "from telegram"
        assert wa_history[0]["content"] == "from whatsapp"

    @pytest.mark.asyncio
    async def test_relay_without_history_still_works(self) -> None:
        """Backward compat: no conversation_history → single-message relay."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.webhook.models import WebhookMessage, WebhookResponse
        from src.webhook.relay import WebhookRelayPipeline

        sanitizer = MagicMock()
        sanitizer.sanitize.return_value = MagicMock(clean="hello", injection_detected=False)
        pipeline = WebhookRelayPipeline(
            sanitizer=sanitizer,
            upstream_url="http://openclaw:3000",
            upstream_token="tok",
        )

        msg = WebhookMessage(source="telegram", text="hello", sender_id="u1", metadata={})

        with patch.object(pipeline, "_forward_to_upstream", new_callable=AsyncMock) as mock_fwd:
            mock_fwd.return_value = WebhookResponse(text="world", status_code=200)
            result = await pipeline.relay(msg)

        assert result.text == "world"
        sent_body = mock_fwd.call_args[0][0]
        assert sent_body["messages"] == [{"role": "user", "content": "hello"}]
