from app.services.discovery_types import DiscoveredNetworkRequest
from app.services.network_classifier import API, ASSET, GRAPHQL, PAGE, WEBSOCKET, classify_request


def _req(**kwargs) -> DiscoveredNetworkRequest:
    defaults = dict(method="GET", url="https://example.com/x", origin="https://example.com", path="/x")
    defaults.update(kwargs)
    return DiscoveredNetworkRequest(**defaults)


def test_xhr_json_is_api_even_without_api_substring():
    req = _req(url="https://example.com/rest/products/1", path="/rest/products/1",
               resource_type="xhr", response_content_type="application/json; charset=utf-8")
    assert classify_request(req) == API
    assert "/api/" not in req.url


def test_document_is_page():
    req = _req(resource_type="document", response_content_type="text/html")
    assert classify_request(req) == PAGE


def test_stylesheet_is_asset():
    req = _req(url="https://example.com/style.css", path="/style.css", resource_type="stylesheet")
    assert classify_request(req) == ASSET


def test_graphql_path_with_fetch_and_json_is_graphql():
    req = _req(url="https://example.com/graphql", path="/graphql",
               resource_type="fetch", content_type="application/json",
               response_content_type="application/json")
    assert classify_request(req) == GRAPHQL


def test_websocket_url_scheme_is_websocket():
    req = _req(url="wss://example.com/socket", path="/socket", resource_type="websocket")
    assert classify_request(req) == WEBSOCKET


def test_fetch_returning_json_is_api_regardless_of_path_shape():
    req = _req(url="https://example.com/whatever/shape", path="/whatever/shape",
               resource_type="fetch", response_content_type="application/json")
    assert classify_request(req) == API
