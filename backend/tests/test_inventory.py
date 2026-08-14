from app.services.inventory import API, PAGE, UPLOAD, AttackSurfaceInventory, normalized_route
from app.services.discovery_types import DiscoveredForm, DiscoveredParam, UploadEndpoint


def test_normalized_route_collapses_id_segments():
    assert normalized_route("https://t/rest/products/1") == normalized_route("https://t/rest/products/2")
    assert "{id}" in normalized_route("https://t/rest/products/1")


def test_unique_ids_and_param_attachment():
    inv = AttackSurfaceInventory()
    p1 = inv.add_discovered_param(DiscoveredParam(url="https://t/search?q=x", name="q", param_type="query"))
    p2 = inv.add_discovered_param(DiscoveredParam(url="https://t/rest/login", name="email", param_type="json", method="POST"))
    assert p1.parameter_id == "pm_0001"
    assert p2.parameter_id == "pm_0002"
    assert inv.endpoint(p1.endpoint_id).endpoint_id == "ep_0001"
    # json param's endpoint classified as API
    assert inv.endpoint(p2.endpoint_id).kind == API


def test_param_dedup_across_id_variants():
    inv = AttackSurfaceInventory()
    assert inv.add_discovered_param(DiscoveredParam(url="https://t/p/1?sort=a", name="sort", param_type="query")) is not None
    # same normalized route + same param name = deduped
    assert inv.add_discovered_param(DiscoveredParam(url="https://t/p/2?sort=b", name="sort", param_type="query")) is None


def test_form_and_upload_kinds():
    inv = AttackSurfaceInventory()
    inv.add_form(DiscoveredForm(url="https://t/contact", method="POST", params=["name"]))
    up = inv.add_upload(UploadEndpoint(url="https://t/upload", method="POST", field_name="file"))
    assert up.kind == UPLOAD
    assert any(p.name == "name" and p.location == "form" for p in inv.parameters)


def test_counts_reports_real_discovery():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(DiscoveredParam(url="https://t/rest/x", name="a", param_type="json", method="POST"))
    counts = inv.counts()
    assert counts["parameters"] == 1
    assert counts["apis"] == 1
