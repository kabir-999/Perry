from app.services.js_analyzer import extract_paths, extract_websocket_urls

BUNDLE = """
fetch("https://api.example.com/v2/orders").then(r => r.json());
axios.post("/rest/user/login", data);
const client = new HttpClient(); client.get("/internal/reports");
xhr.open("GET", "https://other.example.com/rest/products");
const ws = new WebSocket("wss://example.com/socket");
const q = `query GetUser($id: ID!) { user(id: $id) { name } }`;
"""


def test_call_patterns_extract_absolute_and_relative_paths():
    paths = extract_paths(BUNDLE)
    assert "/v2/orders" in paths
    assert "/rest/user/login" in paths
    assert "/internal/reports" in paths
    assert "/rest/products" in paths


def test_graphql_operation_literal_implies_graphql_endpoint():
    assert "/graphql" in extract_paths(BUNDLE)


def test_websocket_call_is_collected_separately_not_as_a_path():
    urls = extract_websocket_urls(BUNDLE)
    assert "wss://example.com/socket" in urls


def test_no_call_patterns_in_bundle_yields_no_extras():
    assert extract_paths("const x = 1;") == set()
    assert extract_websocket_urls("const x = 1;") == set()
