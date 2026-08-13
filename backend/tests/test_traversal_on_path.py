from app.services.security_checks import check_path_traversal_on_path
from fixtures import FakeFetcher, ok_result

PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash"


async def test_resource_existing_alone_is_not_traversal():
    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text="just a normal file")

    fetcher = FakeFetcher(responder)
    findings = await check_path_traversal_on_path(fetcher, "https://example.com/uploads/report.pdf")
    assert findings == []


async def test_passwd_shaped_content_new_relative_to_baseline_is_flagged():
    def responder(url, **kwargs):
        if "etc" in url or "%2e%2e" in url or ".." in url:
            return ok_result(url, status_code=200, text=f"leaked:\n{PASSWD_LINE}\n")
        return ok_result(url, status_code=200, text="just a normal file")

    fetcher = FakeFetcher(responder)
    findings = await check_path_traversal_on_path(fetcher, "https://example.com/uploads/report.pdf")
    assert len(findings) == 1
    assert findings[0].category == "input_validation"
    assert findings[0].confidence == "potential"


async def test_passwd_shaped_content_already_in_baseline_is_not_flagged():
    """A soft-404/catch-all page that always contains passwd-shaped text
    (coincidentally, or as part of some unrelated content) must not be
    reported just because the traversal probe also saw it."""

    def responder(url, **kwargs):
        return ok_result(url, status_code=200, text=f"same page:\n{PASSWD_LINE}\n")

    fetcher = FakeFetcher(responder)
    findings = await check_path_traversal_on_path(fetcher, "https://example.com/uploads/report.pdf")
    assert findings == []


async def test_url_with_no_path_segment_is_skipped():
    fetcher = FakeFetcher(lambda url, **kwargs: ok_result(url))
    findings = await check_path_traversal_on_path(fetcher, "https://example.com/")
    assert findings == []
    assert fetcher.calls == []
