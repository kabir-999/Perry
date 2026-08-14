from app.services.auth_discovery import detect_auth_surface
from app.services.discovery_types import DiscoveredForm, DiscoveredNetworkRequest, DiscoveredPath


def test_detects_login_form_bearer_and_jwt_shape():
    pages = [DiscoveredPath(url="https://target/rest/user/login")]
    forms = [DiscoveredForm(url="https://target/rest/user/login", method="POST",
                             params=["email", "password"])]
    reqs = [
        DiscoveredNetworkRequest(
            method="GET", url="https://target/rest/products", origin="https://target",
            path="/rest/products",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.abc123sig"},
        ),
    ]
    surface = detect_auth_surface(pages, forms, reqs)
    assert surface.login_urls
    assert surface.bearer_token_seen
    assert surface.jwt_shaped_tokens_seen
    assert surface.has_auth_surface


def test_no_auth_evidence_at_all_is_honestly_reported():
    surface = detect_auth_surface([], [], [])
    assert not surface.has_auth_surface
    assert not surface.login_urls
    assert not surface.session_cookie_names


def test_session_cookie_detected_from_set_cookie_header():
    reqs = [
        DiscoveredNetworkRequest(
            method="GET", url="https://target/rest/products", origin="https://target",
            path="/rest/products",
            response_headers={"set-cookie": "connect.sid=abc123; Path=/; HttpOnly"},
        ),
    ]
    surface = detect_auth_surface([], [], reqs)
    assert "connect.sid" in surface.session_cookie_names
    assert surface.has_auth_surface


def test_generic_post_form_with_password_and_identity_fields_is_login():
    forms = [DiscoveredForm(url="https://target/rest/auth", method="POST",
                             params=["username", "password"])]
    surface = detect_auth_surface([], forms, [])
    assert "https://target/rest/auth" in surface.login_urls
