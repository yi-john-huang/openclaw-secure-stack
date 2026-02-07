"""Data models for webhook relay pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WebhookMessage:
    """Normalized inbound webhook message for pipeline processing."""

    source: str  # "telegram" or "whatsapp"
    text: str
    sender_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookResponse:
    """Pipeline response to return to the originating platform."""

    text: str
    status_code: int
