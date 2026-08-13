from app.services.discovery_types import UploadEndpoint
from app.services.security_checks import check_upload_endpoint
from fixtures import FakeFetcher, ok_result


def _upload(field_name="file") -> UploadEndpoint:
    return UploadEndpoint(url="https://example.com/upload", method="POST", field_name=field_name)


async def test_endpoint_alone_is_not_a_finding_when_everything_is_rejected():
    """Detected != tested-and-vulnerable. If every canary is rejected,
    validation is working and there must be no finding from this check."""

    def responder(url, **kwargs):
        return ok_result(url, status_code=415)  # rejected every time

    fetcher = FakeFetcher(responder)
    findings = await check_upload_endpoint(fetcher, _upload())
    assert findings == []


async def test_accepting_disallowed_type_is_flagged_as_weak_validation():
    def responder(url, **kwargs):
        return ok_result(url, status_code=201)  # accepts everything

    fetcher = FakeFetcher(responder)
    findings = await check_upload_endpoint(fetcher, _upload())
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "disallowed" in findings[0].title.lower()


async def test_accepting_only_benign_canary_is_low_severity_not_weak_validation():
    calls = {"n": 0}

    def responder(url, **kwargs):
        calls["n"] += 1
        files = kwargs.get("files") or {}
        # Only accept the plain-text canary; reject the disallowed/traversal ones.
        _, (filename, _content, _ct) = next(iter(files.items()))
        if filename == "sentinel_canary.txt":
            return ok_result(url, status_code=200)
        return ok_result(url, status_code=415)

    fetcher = FakeFetcher(responder)
    findings = await check_upload_endpoint(fetcher, _upload())
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].category == "configuration"


async def test_accessible_uploaded_content_escalates_to_confirmed():
    """Only escalate to a verified/confirmed finding when Sentinel can
    actually fetch back its own canary content — never guess."""

    def responder(url, **kwargs):
        if kwargs.get("files"):
            return ok_result(
                url, status_code=201, headers={"location": "/uploads/sentinel_canary.php"}
            )
        # The follow-up GET to confirm accessibility.
        return ok_result(url, status_code=200, text="sentinel-upload-canary")

    fetcher = FakeFetcher(responder)
    findings = await check_upload_endpoint(fetcher, _upload())
    confirmed = [f for f in findings if f.confidence == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].severity == "high"
    assert confirmed[0].title == "Uploaded file is publicly accessible"
