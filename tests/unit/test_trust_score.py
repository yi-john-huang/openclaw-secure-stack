"""Tests for trust score computation."""

from __future__ import annotations

from src.scanner.trust_score import compute_trust_score


def test_high_trust_score_for_reputable_skill():
    score = compute_trust_score(
        author_reputation=90, download_count=10000,
        community_reviews=50, last_update_days=7,
    )
    assert score.overall >= 70


def test_low_trust_score_for_unknown_author():
    score = compute_trust_score(
        author_reputation=0, download_count=5,
        community_reviews=0, last_update_days=365,
    )
    assert score.overall <= 30


def test_score_clamped_0_100():
    score = compute_trust_score(
        author_reputation=100, download_count=1000000,
        community_reviews=1000, last_update_days=0,
    )
    assert 0 <= score.overall <= 100


def test_zero_inputs():
    score = compute_trust_score()
    assert score.overall >= 0
    assert score.overall <= 100
