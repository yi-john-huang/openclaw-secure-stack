"""Trust score computation for skills."""

from __future__ import annotations

from src.models import TrustScore


def compute_trust_score(
    author_reputation: int = 0,
    download_count: int = 0,
    community_reviews: int = 0,
    last_update_days: int = 0,
) -> TrustScore:
    """Compute a 0-100 trust score based on skill metadata factors.

    Weights: author_reputation 40%, downloads 20%, reviews 20%, recency 20%.
    """
    # Normalize download count (log scale, cap at 100)
    import math

    download_score = min(100, int(math.log10(max(download_count, 1)) * 25))

    # Normalize reviews (cap at 100)
    review_score = min(100, community_reviews * 2)

    # Recency: 0 days = 100, 365+ days = 0
    recency_score = max(0, 100 - int(last_update_days * 100 / 365))

    # Clamp author reputation
    author_score = max(0, min(100, author_reputation))

    overall = int(
        author_score * 0.4
        + download_score * 0.2
        + review_score * 0.2
        + recency_score * 0.2
    )
    overall = max(0, min(100, overall))

    return TrustScore(
        overall=overall,
        author_reputation=author_score,
        download_count=download_count,
        community_reviews=community_reviews,
        last_update_days=last_update_days,
    )
