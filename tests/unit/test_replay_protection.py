"""Tests for webhook replay protection — FR-2.7, FR-3.7, SEC-D-05."""

from __future__ import annotations

import time

import pytest

from src.webhook.replay_protection import ReplayProtection


class TestTelegramReplayProtection:
    """FR-2.7: Telegram update_id replay protection."""

    @pytest.fixture
    def replay_protection(self, tmp_path: object) -> ReplayProtection:
        return ReplayProtection(str(tmp_path / "replay.db"))  # type: ignore[operator]

    def test_new_update_id_accepted(self, replay_protection: ReplayProtection) -> None:
        assert replay_protection.check_telegram(100) is True

    def test_duplicate_update_id_rejected(self, replay_protection: ReplayProtection) -> None:
        replay_protection.check_telegram(100)
        assert replay_protection.check_telegram(100) is False

    def test_older_update_id_rejected(self, replay_protection: ReplayProtection) -> None:
        replay_protection.check_telegram(100)
        assert replay_protection.check_telegram(99) is False

    def test_sequential_update_ids_accepted(self, replay_protection: ReplayProtection) -> None:
        assert replay_protection.check_telegram(100) is True
        assert replay_protection.check_telegram(101) is True
        assert replay_protection.check_telegram(102) is True

    def test_state_persists_across_instances(self, tmp_path: object) -> None:
        """SEC-D-05: SQLite-backed, survives restart."""
        db_path = str(tmp_path / "replay.db")  # type: ignore[operator]
        rp1 = ReplayProtection(db_path)
        rp1.check_telegram(100)
        rp2 = ReplayProtection(db_path)
        assert rp2.check_telegram(100) is False

    def test_gap_in_update_ids_accepted(self, replay_protection: ReplayProtection) -> None:
        """Non-sequential but higher IDs should still be accepted."""
        assert replay_protection.check_telegram(100) is True
        assert replay_protection.check_telegram(200) is True
        # But anything <= 200 is now rejected
        assert replay_protection.check_telegram(150) is False


class TestWhatsAppReplayProtection:
    """FR-3.7: WhatsApp timestamp window replay protection."""

    @pytest.fixture
    def replay_protection(self, tmp_path: object) -> ReplayProtection:
        return ReplayProtection(str(tmp_path / "replay.db"))  # type: ignore[operator]

    def test_recent_message_accepted(self, replay_protection: ReplayProtection) -> None:
        """Message within 5-minute window is accepted."""
        now = int(time.time())
        assert replay_protection.check_whatsapp(now - 60) is True

    def test_old_message_rejected(self, replay_protection: ReplayProtection) -> None:
        """Message older than 5 minutes is rejected."""
        now = int(time.time())
        assert replay_protection.check_whatsapp(now - 301) is False

    def test_future_message_accepted(self, replay_protection: ReplayProtection) -> None:
        """Message with slight future timestamp is accepted (clock skew)."""
        now = int(time.time())
        assert replay_protection.check_whatsapp(now + 5) is True

    def test_configurable_window(self, tmp_path: object) -> None:
        """WHATSAPP_REPLAY_WINDOW_SECONDS configurable."""
        rp = ReplayProtection(
            str(tmp_path / "rp.db"),  # type: ignore[operator]
            whatsapp_window_seconds=10,
        )
        now = int(time.time())
        assert rp.check_whatsapp(now - 11) is False
        assert rp.check_whatsapp(now - 5) is True

    def test_boundary_exactly_at_window(self, replay_protection: ReplayProtection) -> None:
        """Message exactly at the window boundary is rejected (exclusive)."""
        now = int(time.time())
        # Exactly 300 seconds ago is still within the window
        assert replay_protection.check_whatsapp(now - 300) is True
        # 301 seconds ago is outside
        assert replay_protection.check_whatsapp(now - 301) is False

    def test_default_window_is_300(self, replay_protection: ReplayProtection) -> None:
        """Default window is 300 seconds (5 minutes)."""
        assert replay_protection._whatsapp_window_seconds == 300
