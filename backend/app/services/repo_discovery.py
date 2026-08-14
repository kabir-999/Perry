"""Automatic discovery of the public source repository behind a website.

The scanner collects several independent signals from the site itself (an
exposed .git/config, manifests, links, GitHub Pages DNS, provider search),
each with its own confidence, and then *verifies* the best candidates against
the provider API: a repository whose `homepage` points back at the target
domain is treated as confirmed. The user never has to know the repo URL.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import httpx

from app.config import settings
from app.services.discovery_types import CrawlResult
from app.services.http_client import Fetcher
from app.services.scope import TargetScope, strip_public_suffix


@dataclass
class RepoCandidate:
    provider: str        # "github" | "gitlab"
    owner: str
    name: str
    url: str
    confidence: float    # 0.0-1.0
    discovery_source: str  # "git_config" | "page_link" | "package_json" | ...
    verified: bool = False  # provider API confirmed it points back at the site

    def key(self) -> str:
        return f"{self.provider}:{self.owner.lower()}:{self.name.lower()}"


_GITHUB_RE = re.compile(r"https?://(?:www\.)?github\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_\.-]+)/?")
_GITLAB_RE = re.compile(r"https?://(?:www\.)?gitlab\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_\.-]+)/?")

# Skip common false positives
_SKIP_REPOS = {"github", "github.io", "actions", "features", "sponsors", "login"}
_SKIP_OWNERS = {
    "github", "gitlab-org", "vercel", "netlify", "heroku", "aws", "docker",
    "facebook", "google", "microsoft", "apple", "twitter", "sponsors",
    "readme", "topics", "orgs", "features", "about", "pricing",
}

# Repos matching these names are almost never the site's own source.
_GENERIC_NAMES = {"docs", "website", "web", "site", "www", "blog", "app"}

# Signals that name the repository authoritatively rather than incidentally,
# so the skip-lists don't apply to them.
_TRUSTED_SOURCES = {
    "git_config", "package_json", "composer_json", "github_pages_dns",
    "user_supplied",
}

# A search hit is only ever a lead: it must be confirmed by the provider API
# before we will clone and scan it.
_REQUIRES_VERIFICATION = {"github_search"}

_API_TIMEOUT = 6.0
# Hard ceiling on provider API calls per scan: unauthenticated GitHub allows
# only 60 requests/hour per IP, so verification stays deliberately frugal.
_MAX_API_CALLS = 14


def parse_repo_url(url: str) -> Optional[RepoCandidate]:
    """Parse an explicit GitHub/GitLab repo URL (advanced/API use only).

    Returns None if the URL is not a recognisable repository URL. An
    explicitly supplied repo gets confidence 1.0 — there is nothing to guess.
    """
    url = (url or "").strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    url = url.split("#")[0].split("?")[0].rstrip("/")

    gh_match = _GITHUB_RE.match(url)
    gl_match = _GITLAB_RE.match(url)
    match = gh_match or gl_match
    if not match:
        return None

    owner, name = match.groups()
    if name.endswith(".git"):
        name = name[:-4]

    provider = "github" if gh_match else "gitlab"
    return RepoCandidate(
        provider=provider,
        owner=owner,
        name=name,
        url=f"https://{provider}.com/{owner}/{name}",
        confidence=1.0,
        discovery_source="user_supplied",
        verified=True,
    )


# ----------------------------------------------------------------- collection


class _Candidates:
    """Accumulates candidates, keeping the highest confidence per repo."""

    def __init__(self, scope: TargetScope) -> None:
        self._items: dict[str, RepoCandidate] = {}
        self._scope = scope
        self._domain_labels = _domain_labels(scope.hostname)

    def add(self, url: str, source: str, confidence: float) -> None:
        cand = parse_repo_url(url)
        if cand is None:
            return

        # A repo or owner named after the site is a much better bet.
        matches_domain = (
            cand.owner.lower() in self._domain_labels
            or cand.name.lower() in self._domain_labels
        )

        # The skip-lists exist to drop incidental links ("Deployed on Vercel",
        # a badge pointing at github.com/facebook/react). They must not fire
        # when the site genuinely belongs to that owner — swr.vercel.app really
        # is vercel/swr, and microsoft.github.io really is microsoft's.
        if not matches_domain and source not in _TRUSTED_SOURCES:
            if cand.owner.lower() in _SKIP_OWNERS or cand.name.lower() in _SKIP_REPOS:
                return

        if matches_domain:
            confidence += 0.2
        elif cand.name.lower() in _GENERIC_NAMES:
            confidence -= 0.1

        cand.confidence = max(0.0, min(1.0, confidence))
        cand.discovery_source = source
        cand.verified = False

        existing = self._items.get(cand.key())
        if existing is None or existing.confidence < cand.confidence:
            self._items[cand.key()] = cand

    def all(self) -> list[RepoCandidate]:
        return sorted(self._items.values(), key=lambda c: c.confidence, reverse=True)


# Infrastructure-ish host prefixes that say nothing about the project name.
_GENERIC_HOST_LABELS = {
    "www", "web", "m", "mobile", "static", "cdn", "assets", "api", "app",
    "site", "portal", "public",
}


def _domain_labels(hostname: str) -> set[str]:
    """Labels worth matching a repo/owner name against.

    The registry/platform suffix is stripped first: on `myapp.vercel.app` the
    site's name is `myapp`, and treating `vercel` as a match hint would boost
    the platform vendor's own repositories over the user's.
    """
    stem = strip_public_suffix(hostname.lower())
    parts = [p for p in stem.split(".") if p and p not in _GENERIC_HOST_LABELS]
    labels: set[str] = set(parts)
    for p in parts:
        labels.add(p.replace("-", ""))
        labels.update(seg for seg in p.split("-") if len(seg) > 2)
    return {l for l in labels if l}


async def _from_git_config(fetcher: Fetcher, cands: _Candidates, scope: TargetScope) -> None:
    """An exposed .git directory leaks the remote URL outright — definitive."""
    res = await fetcher.fetch(f"{scope.origin}/.git/config")
    if not res.ok or "[core]" not in res.text:
        return
    for match in re.finditer(r"url\s*=\s*(\S+)", res.text):
        raw = match.group(1)
        # Normalise scp-style remotes (git@github.com:owner/repo.git).
        raw = re.sub(r"^git@(github|gitlab)\.com:", r"https://\1.com/", raw)
        cands.add(raw, "git_config", 0.99)


async def _from_manifests(fetcher: Fetcher, cands: _Candidates, scope: TargetScope) -> None:
    """Manifests and well-known files that commonly name the repository."""

    async def _package_json() -> None:
        res = await fetcher.fetch(f"{scope.origin}/package.json")
        if not res.ok or "json" not in res.content_type.lower():
            return
        try:
            pkg = json.loads(res.text)
        except (ValueError, TypeError):
            return
        repo = pkg.get("repository", "")
        if isinstance(repo, dict):
            repo = repo.get("url", "")
        if isinstance(repo, str) and repo:
            cands.add(repo.removeprefix("git+"), "package_json", 0.9)
        for key in ("homepage", "bugs"):
            val = pkg.get(key)
            if isinstance(val, dict):
                val = val.get("url", "")
            if isinstance(val, str) and val:
                cands.add(val, "package_json", 0.75)

    async def _composer_json() -> None:
        res = await fetcher.fetch(f"{scope.origin}/composer.json")
        if not res.ok or "json" not in res.content_type.lower():
            return
        try:
            pkg = json.loads(res.text)
        except (ValueError, TypeError):
            return
        source = (pkg.get("support") or {}).get("source", "")
        if isinstance(source, str) and source:
            cands.add(source, "composer_json", 0.85)

    async def _text_file(path: str, source: str, confidence: float) -> None:
        res = await fetcher.fetch(f"{scope.origin}{path}")
        if not res.ok:
            return
        for match in re.finditer(r"https?://(?:www\.)?(?:github|gitlab)\.com/\S+", res.text):
            cands.add(match.group(0).rstrip(".,);\"'"), source, confidence)

    await asyncio.gather(
        _package_json(),
        _composer_json(),
        _text_file("/.well-known/security.txt", "security_txt", 0.7),
        _text_file("/security.txt", "security_txt", 0.7),
        _text_file("/humans.txt", "humans_txt", 0.65),
        return_exceptions=True,
    )


def _from_page_links(cands: _Candidates, crawl_result: CrawlResult) -> None:
    """Repo links in the page itself (footer "source" links, README badges)."""
    for link in crawl_result.external_links:
        cands.add(link, "page_link", 0.6)


async def _github_pages_owner(scope: TargetScope) -> Optional[str]:
    """If the site is served by GitHub Pages, its hostname names the owner.

    Either the site *is* `<owner>.github.io`, or a custom domain CNAMEs to it.
    """
    host = scope.hostname.lower()
    if host.endswith(".github.io"):
        return host.removesuffix(".github.io").split(".")[-1]

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 4.0

    for host in (scope.hostname, f"www.{scope.hostname}"):
        try:
            answer = await resolver.resolve(host, "CNAME")
        except (dns.exception.DNSException, ValueError):
            continue
        for record in answer:
            target = str(record.target).rstrip(".").lower()
            if target.endswith(".github.io"):
                return target.removesuffix(".github.io")
    return None


# --------------------------------------------------------------- provider API


class _GitHubApi:
    """Small, budgeted GitHub API helper. Degrades to a no-op on rate limits."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._calls = 0
        self.available = True
        headers = {"Accept": "application/vnd.github+json"}
        token = getattr(settings, "GITHUB_TOKEN", None)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._headers = headers

    async def get(self, path: str, params: dict | None = None) -> object | None:
        if not self.available or self._calls >= _MAX_API_CALLS:
            return None
        self._calls += 1
        try:
            res = await self._client.get(
                f"https://api.github.com{path}",
                headers=self._headers,
                params=params,
                timeout=_API_TIMEOUT,
            )
        except (httpx.HTTPError, asyncio.TimeoutError):
            return None
        if res.status_code in (403, 429):
            # Rate limited — stop making calls rather than stalling the scan.
            self.available = False
            return None
        if res.status_code != 200:
            return None
        try:
            return res.json()
        except ValueError:
            return None


async def _from_github_search(api: _GitHubApi, cands: _Candidates, scope: TargetScope) -> None:
    """Ask GitHub which repositories mention this domain."""
    data = await api.get(
        "/search/repositories",
        params={"q": scope.hostname, "sort": "stars", "per_page": "5"},
    )
    if not isinstance(data, dict):
        return
    for item in data.get("items", [])[:5]:
        if not isinstance(item, dict):
            continue
        html_url = item.get("html_url", "")
        if isinstance(html_url, str) and html_url:
            # Low base confidence — search matches are only a lead until the
            # verification step confirms the repo points back at the site.
            cands.add(html_url, "github_search", 0.45)


async def _from_owner_repos(api: _GitHubApi, cands: _Candidates, owner: str, source: str) -> None:
    """List a known owner's repos (used once GitHub Pages reveals the owner)."""
    data = await api.get(f"/users/{owner}/repos", params={"per_page": "100", "sort": "updated"})
    if not isinstance(data, list):
        return
    for item in data[:100]:
        if isinstance(item, dict) and isinstance(item.get("html_url"), str):
            cands.add(item["html_url"], source, 0.55)


async def _verify(api: _GitHubApi, cand: RepoCandidate, scope: TargetScope) -> None:
    """Confirm the repo exists and check whether it points back at the site.

    A matching `homepage` is the strongest signal available short of an
    exposed .git/config, and a 404 drops the candidate entirely so we never
    try to clone a repo that isn't there.
    """
    if cand.provider != "github":
        return
    data = await api.get(f"/repos/{cand.owner}/{cand.name}")
    if data is None:
        return  # inconclusive (rate limited or transient) — leave as-is
    if not isinstance(data, dict) or data.get("full_name") is None:
        cand.confidence = 0.0
        return

    homepage = data.get("homepage") or ""
    if isinstance(homepage, str) and homepage:
        parts = urlsplit(homepage if "//" in homepage else f"//{homepage}")
        host = (parts.hostname or "").lower().removeprefix("www.")
        # The path must be the site root too. On a shared Pages domain many
        # sibling projects point at <owner>.github.io/<project>/ — matching on
        # hostname alone would confirm the wrong repository.
        is_root = not parts.path.strip("/")
        if host and host == scope.hostname.lower().removeprefix("www.") and is_root:
            cand.confidence = 0.97
            cand.verified = True
            return

    blob = " ".join(
        str(data.get(k) or "") for k in ("description", "homepage", "name")
    ).lower()
    if scope.hostname.lower() in blob:
        cand.confidence = min(1.0, cand.confidence + 0.2)
    if data.get("fork"):
        cand.confidence -= 0.15
    if data.get("archived"):
        cand.confidence -= 0.05


# ------------------------------------------------------------------ orchestrator


async def discover_repository(
    fetcher: Fetcher, scope: TargetScope, crawl_result: CrawlResult
) -> Optional[RepoCandidate]:
    """Find the public GitHub/GitLab repository belonging to the website."""
    cands = _Candidates(scope)

    # Signals from the site itself (cheap, all against the in-scope origin).
    _from_page_links(cands, crawl_result)
    await asyncio.gather(
        _from_git_config(fetcher, cands, scope),
        _from_manifests(fetcher, cands, scope),
        return_exceptions=True,
    )

    # An exposed remote URL is definitive; skip the API work entirely.
    for cand in cands.all():
        if cand.discovery_source == "git_config":
            cand.verified = True
            return cand

    async with httpx.AsyncClient(follow_redirects=True) as client:
        api = _GitHubApi(client)

        pages_owner = await _github_pages_owner(scope)
        if pages_owner:
            # A user/org page's repo is literally <owner>.github.io.
            cands.add(
                f"https://github.com/{pages_owner}/{pages_owner}.github.io",
                "github_pages_dns",
                0.8,
            )
            await _from_owner_repos(api, cands, pages_owner, "github_pages_dns")

        if not cands.all():
            await _from_github_search(api, cands, scope)

        # Verify the strongest few leads; stop as soon as one is confirmed.
        for cand in cands.all()[:4]:
            await _verify(api, cand, scope)
            if cand.verified:
                return cand

        # Nothing confirmed — fall back to search leads if we had no candidates
        # worth verifying at all.
        if not cands.all() or max(c.confidence for c in cands.all()) < settings.REPO_MIN_CONFIDENCE:
            await _from_github_search(api, cands, scope)
            for cand in cands.all()[:3]:
                if cand.discovery_source == "github_search":
                    await _verify(api, cand, scope)
                    if cand.verified:
                        return cand

    min_confidence = getattr(settings, "REPO_MIN_CONFIDENCE", 0.6)
    for cand in cands.all():
        # A bare search hit that the API never confirmed is a guess; cloning
        # and reporting findings from the wrong repository is worse than
        # reporting no source analysis at all.
        if cand.discovery_source in _REQUIRES_VERIFICATION and not cand.verified:
            continue
        if cand.confidence >= min_confidence:
            return cand
    return None
