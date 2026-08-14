import json

from app.services.discovery_types import DiscoveredNetworkRequest
from app.services.parameter_discovery import consolidate_parameters, extract_params_from_network


def test_extracts_query_json_graphql_path_and_header_params():
    reqs = [
        DiscoveredNetworkRequest(
            method="GET", url="https://target/rest/products/1?sort=asc",
            origin="https://target", path="/rest/products/1",
            headers={"X-Custom-Trace": "abc"},
        ),
        DiscoveredNetworkRequest(
            method="GET", url="https://target/rest/products/2",
            origin="https://target", path="/rest/products/2",
        ),
        DiscoveredNetworkRequest(
            method="POST", url="https://target/rest/user/login",
            origin="https://target", path="/rest/user/login",
            headers={"content-type": "application/json"}, content_type="application/json",
            body=json.dumps({"email": "a@b.com", "password": "x"}),
        ),
        DiscoveredNetworkRequest(
            method="POST", url="https://target/graphql",
            origin="https://target", path="/graphql",
            headers={"content-type": "application/json"}, content_type="application/json",
            body=json.dumps({"query": "query GetUser($id: ID!) { user(id: $id) { name } }",
                              "variables": {"id": "42"}}),
        ),
    ]
    params = extract_params_from_network(reqs)
    shapes = {(p.param_type, p.name) for p in params}

    assert ("query", "sort") in shapes
    assert ("json", "email") in shapes
    assert ("json", "password") in shapes
    assert ("graphql_variable", "id") in shapes
    assert ("header", "X-Custom-Trace") in shapes
    assert any(t == "path" for t, _ in shapes)


def test_standard_headers_are_never_reported_as_parameters():
    reqs = [
        DiscoveredNetworkRequest(
            method="GET", url="https://target/x", origin="https://target", path="/x",
            headers={"Accept": "*/*", "User-Agent": "test", "X-Real": "1"},
        )
    ]
    names = {p.name for p in extract_params_from_network(reqs)}
    assert "Accept" not in names
    assert "User-Agent" not in names
    assert "X-Real" in names


def test_no_network_requests_yields_no_params():
    assert extract_params_from_network([]) == []


def test_consolidate_still_dedupes_across_sources():
    reqs = [
        DiscoveredNetworkRequest(method="GET", url="https://target/x?id=1", origin="https://target", path="/x"),
    ]
    net_params = extract_params_from_network(reqs)
    combined = consolidate_parameters(net_params, net_params)
    assert len(combined) == len(net_params)
