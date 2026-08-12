"""
Response Analyzer.

Turns a raw ``FetchResult`` into structured signals the rest of the scanner
reasons about, and — critically — decides whether a response represents a
*real* resource or a soft-404.

Many sites return HTTP 200 for non-existent paths (soft-404s). Treating
every 200 as a discovery produces a flood of false positives, so we
fingerprint the site's "not found" behaviour up front and compare candidate
responses against it by similarity rather than by status code alone.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from app.services.http_client import FetchResult

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_NUM_RE = re.compile(r"\d+")


def _visible_text(html: str) -> str:
    text = _TAG_RE.sub(" ", html)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def _shingles(text: str, size: int = 3) -> set[int]:
    """Word-trigram hash set, for Jaccard similarity between two bodies."""
    words = text.lower().split()
    if len(words) < size:
        return {hash(text.lower())} if text else set()
    return {
        hash(" ".join(words[i : i + size])) for i in range(len(words) - size + 1)
    }


def jaccard(a: set[int], b: set[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


@dataclass
class AnalyzedResponse:
    url: str
    status_code: int | None
    content_type: str
    length: int
    redirected: bool
    redirect_chain: list[tuple[int, str]]
    title: str
    visible_text: str
    fingerprint: str
    shingles: set[int] = field(default_factory=set)
    error: str | None = None

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()

    @property
    def is_json(self) -> bool:
        ct = self.content_type.lower()
        return "json" in ct or "+json" in ct


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def analyze(result: FetchResult) -> AnalyzedResponse:
    """Extract structured signals from a fetch result."""
    if not result.ok:
        return AnalyzedResponse(
            url=result.requested_url,
            status_code=None,
            content_type="",
            length=0,
            redirected=False,
            redirect_chain=[],
            title="",
            visible_text="",
            fingerprint="",
            error=result.error,
        )

    text = result.text
    title_match = _TITLE_RE.search(text)
    title = _visible_text(title_match.group(1)) if title_match else ""
    visible = _visible_text(text) if "html" in result.content_type.lower() else text

    # A stable structural fingerprint: status + content-type family + a
    # length bucket + a hash of the digit-stripped visible text. Digit
    # stripping keeps timestamps/ids from making identical templates differ.
    ct_family = result.content_type.split(";")[0].strip().lower()
    length_bucket = result.body_bytes // 256
    normalized = _NUM_RE.sub("#", visible[:4000])
    digest = hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()[:16]
    fingerprint = f"{result.status_code}:{ct_family}:{length_bucket}:{digest}"

    return AnalyzedResponse(
        url=result.url,
        status_code=result.status_code,
        content_type=result.content_type,
        length=result.body_bytes,
        redirected=bool(result.redirects),
        redirect_chain=result.redirects,
        title=title,
        visible_text=visible,
        fingerprint=fingerprint,
        shingles=_shingles(normalized),
    )


# Verdicts returned by NotFoundProfile.classify().
REAL = "real"
NOT_FOUND = "not_found"
SOFT_404 = "soft_404"
SPA_FALLBACK = "spa_fallback"
SERVER_ERROR = "server_error"
ERROR = "error"

# Verdicts that mean "this path does not represent its own resource".
_NEGATIVE = (NOT_FOUND, SOFT_404, SPA_FALLBACK, ERROR)

# Extensions whose content is never HTML. A single-page app that answers
# /.env or /config.json with its index.html shell is the classic false
# positive this catches.
_NON_HTML_EXTENSIONS = {
    ".env", ".json", ".yml", ".yaml", ".sql", ".bak", ".old", ".log", ".ini",
    ".conf", ".config", ".cfg", ".xml", ".txt", ".pem", ".key", ".crt", ".sh",
    ".zip", ".tar", ".gz", ".db", ".sqlite", ".swp", ".properties", ".toml",
}


def _expects_non_html(path: str) -> bool:
    """True when the requested path should not plausibly return HTML."""
    if not path:
        return False
    tail = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if not tail:
        return False
    # Dotfiles (.env, .htaccess) and version-control internals.
    if tail.startswith("."):
        return True
    if "/.git/" in path.lower() or "/.svn/" in path.lower():
        return True
    dot = tail.rfind(".")
    return dot > 0 and tail[dot:] in _NON_HTML_EXTENSIONS


def _similar(
    a: AnalyzedResponse, b: AnalyzedResponse, threshold: float
) -> bool:
    """Whether two responses are essentially the same page.

    Body similarity is the primary signal, but an SPA shell carries almost no
    visible text, which makes trigram overlap unstable — so an identical
    title, content-type family, and near-identical size counts too.
    """
    if a.fingerprint and a.fingerprint == b.fingerprint:
        return True
    if jaccard(a.shingles, b.shingles) >= threshold:
        return True
    same_family = (
        a.content_type.split(";")[0].strip().lower()
        == b.content_type.split(";")[0].strip().lower()
    )
    if a.is_html and b.is_html and same_family and a.title and a.title == b.title:
        larger = max(a.length, b.length, 1)
        if abs(a.length - b.length) / larger <= 0.05:
            return True
    return False


@dataclass
class NotFoundProfile:
    """Learned "this path does not exist" behaviour for a target.

    Holds three things: the site's not-found samples, the root (`/`) baseline,
    and whether the site behaves like a single-page app that serves its shell
    for unknown routes.
    """

    status_codes: set[int] = field(default_factory=set)
    fingerprints: set[str] = field(default_factory=set)
    samples: list[AnalyzedResponse] = field(default_factory=list)
    root: AnalyzedResponse | None = None
    is_spa: bool = False
    similarity_threshold: float = 0.85

    def classify(
        self, analyzed: AnalyzedResponse, path: str | None = None
    ) -> str:
        """Classify a candidate response against the learned baselines."""
        if analyzed.error is not None or analyzed.status_code is None:
            return ERROR
        status = analyzed.status_code
        if status in (404, 410):
            return NOT_FOUND
        if status >= 500:
            # Server errors are interesting (e.g. stack traces) but are not
            # "resource exists" hits; callers handle them separately.
            return SERVER_ERROR
        if status in (401, 403):
            # Protected but present — a fallback never asks for credentials.
            return REAL
        if not (200 <= status < 400):
            return NOT_FOUND

        # An exact structural match with a known not-found response.
        if analyzed.fingerprint in self.fingerprints:
            return SOFT_404
        for sample in self.samples:
            if sample.status_code != status:
                continue
            if _similar(sample, analyzed, self.similarity_threshold):
                return SOFT_404

        # A non-HTML resource answered with HTML is the site's catch-all
        # route, not the file we asked for.
        if path and _expects_non_html(path) and analyzed.is_html:
            return SPA_FALLBACK

        # The SPA shell served for an unknown route: byte-identical to the
        # root page, or (on a confirmed SPA) essentially the same page.
        if self.root is not None and analyzed.is_html:
            if analyzed.fingerprint == self.root.fingerprint:
                return SPA_FALLBACK
            if self.is_spa and _similar(self.root, analyzed, self.similarity_threshold):
                return SPA_FALLBACK

        return REAL

    def looks_like_not_found(
        self, analyzed: AnalyzedResponse, path: str | None = None
    ) -> bool:
        """Decide whether a candidate response is really a 'not found'."""
        return self.classify(analyzed, path) in _NEGATIVE

    def is_real_hit(
        self, analyzed: AnalyzedResponse, path: str | None = None
    ) -> bool:
        return self.classify(analyzed, path) == REAL


async def learn_not_found_profile(fetcher, origin: str) -> NotFoundProfile:
    """Learn the site's not-found behaviour before any discovery runs.

    Fetches the root page as a baseline plus a set of guaranteed-absent paths
    that mirror the *shapes* we later probe — a bare route, an .html file, a
    directory, a dotfile, an extension file, and a nested path. Servers often
    treat these differently (an SPA rewrites `/admin` to its shell but returns
    a hard 404 for `/foo.json`), so one probe shape is not enough.
    """
    import uuid as _uuid

    probes = [
        f"{origin}/{_uuid.uuid4().hex}",
        f"{origin}/{_uuid.uuid4().hex}.html",
        f"{origin}/nonexistent-{_uuid.uuid4().hex}/",
        f"{origin}/.{_uuid.uuid4().hex}",
        f"{origin}/{_uuid.uuid4().hex}.json",
        f"{origin}/{_uuid.uuid4().hex}/{_uuid.uuid4().hex}",
    ]
    root_result, *results = await fetcher.fetch_many([origin] + probes)

    profile = NotFoundProfile()

    root_analyzed = analyze(root_result)
    if root_analyzed.status_code is not None:
        profile.root = root_analyzed

    for res in results:
        analyzed = analyze(res)
        if analyzed.status_code is None:
            continue
        profile.status_codes.add(analyzed.status_code)
        profile.fingerprints.add(analyzed.fingerprint)
        profile.samples.append(analyzed)

    # An SPA is a site whose unknown routes come back as a 200 HTML page that
    # is essentially the root page.
    if profile.root is not None and profile.root.is_html:
        profile.is_spa = any(
            s.status_code == 200
            and s.is_html
            and _similar(profile.root, s, profile.similarity_threshold)
            for s in profile.samples
        )

    return profile
