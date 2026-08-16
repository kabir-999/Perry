"""
Residual risk-model helpers.

The old CVSS-vector + hardening-model + "top finding + bounded headroom"
aggregation (`calculate_Perry_risk`) has been removed. Risk is now the
pure 5-factor per-finding formula in `risk_engine.py`, and overall
application risk is the highest confirmed finding's score
(`risk_engine.overall_confirmed_risk`) — see ARCHITECTURE.md.

Only two general-purpose helpers survive here, both still used by the new
model: `exposure_multiplier` (breadth tier, consumed by
`risk_engine._exposure`) and `deduplicate` (collapse findings describing one
underlying problem before scoring).
"""
from __future__ import annotations

# Scanner confidence words → numeric strength, used only to keep the strongest
# evidence when merging duplicates.
_CONFIDENCE = {
    "confirmed": 0.95,
    "potential": 0.60,
    "uncertain": 0.35,
    "false_positive": 0.0,
}

# Bounded, diminishing breadth multiplier tiers: (max_urls | None, multiplier).
_EXPOSURE_TIERS = [(1, 1.0), (5, 1.1), (20, 1.2), (None, 1.3)]
_EXPOSURE_CAP = 1.3


def exposure_multiplier(affected_urls: int) -> float:
    """Breadth matters — the same weakness on twenty pages is worse than on
    one — but only within a hard-capped, diminishing band, never linearly."""
    n = max(1, int(affected_urls or 1))
    for limit, mult in _EXPOSURE_TIERS:
        if limit is None or n <= limit:
            return float(mult)
    return _EXPOSURE_CAP


def deduplicate(findings: list) -> list:
    """Merge findings describing one underlying problem.

    Three URLs missing the same five headers is one finding affecting three
    URLs, not fifteen. Modules that independently detect the same issue
    collapse onto the same dedup key; the strongest confidence and widest
    affected set win.
    """
    merged: dict[str, object] = {}
    order: list[str] = []
    for f in findings:
        key = getattr(f, "dedup_key", "") or f"{f.category}|{f.title}|{f.parameter}"
        existing = merged.get(key)
        if existing is None:
            merged[key] = f
            order.append(key)
            continue
        samples = list(
            dict.fromkeys(
                (existing.affected_url_samples or []) + (f.affected_url_samples or [])
            )
        )
        existing.affected_url_samples = samples[:10]
        existing.affected_urls = max(
            existing.affected_urls or 1, f.affected_urls or 1, len(samples)
        )
        if _CONFIDENCE.get(f.confidence, 0) > _CONFIDENCE.get(existing.confidence, 0):
            existing.confidence = f.confidence
    return [merged[k] for k in order]
