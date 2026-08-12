"""
Parameter discovery.

Aggregates and de-duplicates parameters observed by the crawler (query
strings + forms) and the API discovery stage. Does not brute-force hidden
parameters — it consolidates what was actually seen, which the security
checks then probe.
"""
from __future__ import annotations

from app.services.discovery_types import DiscoveredParam


def consolidate_parameters(
    *param_lists: list[DiscoveredParam],
) -> list[DiscoveredParam]:
    seen: dict[str, DiscoveredParam] = {}
    for params in param_lists:
        for p in params:
            if not p.name:
                continue
            key = p.key()
            if key not in seen:
                seen[key] = p
            elif p.example_value and not seen[key].example_value:
                seen[key].example_value = p.example_value
    return list(seen.values())
