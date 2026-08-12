"""
Semantic-version parsing and OSV affected-range evaluation.

An OSV advisory usually carries one range *per maintained major branch*:

    GHSA-664h-wqgq-64gw (mongoose)
        SEMVER  introduced 0       fixed 6.13.10
        SEMVER  introduced 7.0.0   fixed 7.8.10
        SEMVER  introduced 8.0.0   fixed 8.24.1

Reading the first range and reporting "<6.13.10" for an installed 7.8.7 is
wrong twice over: it prints a range the version is not in, and it makes a true
positive look like a false one. The applicable range here is [7.0.0, 7.8.10),
which 7.8.7 *is* inside.

So this module answers two questions together: is the installed version
actually inside an affected interval, and — if so — which interval, so the
report can quote the one that applies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# 1.2.3, 1.2.3-beta.1, 1.2.3+build, 4.17.21, 2.0.0rc1, 1.2.3.post1
_VERSION_RE = re.compile(
    r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[-._]?(a|b|c|rc|alpha|beta|pre|preview|dev|post)\.?(\d*))?"
    r"(?:[-+]([0-9A-Za-z.-]+))?\s*$"
)

# Ordering of pre-release markers; a release outranks all of them.
_PRE_RANK = {
    "dev": -5, "alpha": -4, "a": -4, "pre": -3, "preview": -3,
    "beta": -2, "b": -2, "rc": -1, "c": -1,
}
_RELEASE = 0
_POST = 1


@dataclass(frozen=True)
class Version:
    release: tuple[int, ...]
    stage: int          # -5..-1 pre-release, 0 release, 1 post-release
    stage_num: int

    def key(self) -> tuple:
        # Pad so 1.2 and 1.2.0 compare equal.
        release = self.release + (0,) * (4 - len(self.release))
        return (release, self.stage, self.stage_num)

    def __lt__(self, other: "Version") -> bool:
        return self.key() < other.key()

    def __le__(self, other: "Version") -> bool:
        return self.key() <= other.key()


def parse_version(raw: str) -> Version | None:
    """Parse a version string, or None if it is not one we can order."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text == "0":
        # OSV uses "0" as "from the beginning of time".
        return Version((0, 0, 0, 0), _RELEASE, 0) if text == "0" else None

    match = _VERSION_RE.match(text)
    if not match:
        return None

    parts = [int(g) for g in match.groups()[:4] if g is not None]
    if not parts:
        return None

    marker, marker_num = match.group(5), match.group(6)
    if marker == "post":
        stage, stage_num = _POST, int(marker_num or 0)
    elif marker:
        stage, stage_num = _PRE_RANK.get(marker, -1), int(marker_num or 0)
    else:
        stage, stage_num = _RELEASE, 0

    return Version(tuple(parts), stage, stage_num)


def _events_to_intervals(events: list[dict]) -> list[tuple[str, str, str]]:
    """Collapse OSV events into (introduced, upper, upper_kind) intervals.

    upper_kind is "fixed" (exclusive), "last_affected" (inclusive), or ""
    (open-ended).
    """
    intervals: list[tuple[str, str, str]] = []
    introduced: str | None = None

    for event in events or []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            if introduced is not None:
                intervals.append((introduced, "", ""))
            introduced = str(event["introduced"])
        elif "fixed" in event:
            intervals.append((introduced if introduced is not None else "0",
                              str(event["fixed"]), "fixed"))
            introduced = None
        elif "last_affected" in event:
            intervals.append((introduced if introduced is not None else "0",
                              str(event["last_affected"]), "last_affected"))
            introduced = None

    if introduced is not None:
        intervals.append((introduced, "", ""))
    return intervals


def _in_interval(version: Version, low: str, high: str, kind: str) -> bool:
    low_v = parse_version(low) if low else None
    if low_v is not None and version < low_v:
        return False
    if not high:
        return True
    high_v = parse_version(high)
    if high_v is None:
        return False
    return version <= high_v if kind == "last_affected" else version < high_v


def _describe(low: str, high: str, kind: str) -> str:
    if high and kind == "fixed":
        return f">={low or '0'}, <{high}"
    if high and kind == "last_affected":
        return f">={low or '0'}, <={high}"
    return f">={low or '0'}"


@dataclass
class RangeMatch:
    """The affected interval that the installed version actually falls in."""

    affected: bool
    vulnerable_range: str = ""
    fixed_version: str = ""
    reason: str = ""


def evaluate(vuln: dict, package: str, installed: str) -> RangeMatch:
    """Decide whether ``installed`` is inside any affected range of ``vuln``.

    Returns the *matching* interval, so callers quote the range the version is
    actually in rather than whichever range happened to be listed first.
    """
    version = parse_version(installed)
    if version is None:
        # Unparseable version: we cannot prove it is affected, so we do not
        # claim it is. Saying "unknown" beats inventing a match.
        return RangeMatch(False, reason=f"installed version {installed!r} could not be parsed")

    package_lower = package.lower()
    considered: list[str] = []

    for entry in vuln.get("affected", []) or []:
        if not isinstance(entry, dict):
            continue
        name = ((entry.get("package") or {}).get("name") or "").lower()
        # Exact package match only — substring matching pulls in siblings like
        # "mongoose-paginate" for "mongoose".
        if name and name != package_lower:
            continue

        # An explicit version list is authoritative when present.
        listed = entry.get("versions")
        if isinstance(listed, list) and listed:
            if any(str(v).strip() == installed.strip() for v in listed):
                return RangeMatch(True, vulnerable_range="listed in advisory",
                                  reason="installed version is named in the advisory")
            considered.append(f"{len(listed)} explicit versions")

        for rng in entry.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            if str(rng.get("type", "")).upper() == "GIT":
                continue  # commit ranges say nothing about a released version
            for low, high, kind in _events_to_intervals(rng.get("events", [])):
                described = _describe(low, high, kind)
                considered.append(described)
                if _in_interval(version, low, high, kind):
                    return RangeMatch(
                        True,
                        vulnerable_range=described,
                        fixed_version=high if kind == "fixed" else "",
                        reason=f"{installed} is within {described}",
                    )

    return RangeMatch(
        False,
        reason=(
            f"{installed} is outside every affected range"
            + (f" ({'; '.join(considered[:3])})" if considered else "")
        ),
    )
