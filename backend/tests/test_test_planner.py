from app.services.attacks import catalog as C
from app.services.discovery_types import DiscoveredParam, UploadEndpoint
from app.services.inventory import AttackSurfaceInventory
from app.services.test_planner import eligible_counts, plan_tests


def _inv():
    inv = AttackSurfaceInventory()
    inv.add_discovered_param(DiscoveredParam(url="https://t/search?q=x", name="q", param_type="query"))
    inv.add_discovered_param(DiscoveredParam(url="https://t/dl?file=a", name="file", param_type="query"))
    inv.add_discovered_param(DiscoveredParam(url="https://t/go?next=x", name="next", param_type="query"))
    inv.add_discovered_param(DiscoveredParam(url="https://t/rest/login", name="email", param_type="json", method="POST"))
    inv.add_upload(UploadEndpoint(url="https://t/upload", method="POST", field_name="file"))
    return inv


def test_each_attack_only_selects_eligible_targets():
    inv = _inv()
    ec = eligible_counts(plan_tests(inv))
    # path traversal is now probed on ALL injectable params (name heuristics
    # only prioritise) — q, file, next (query) + email (json) = 4.
    assert ec[C.PATH_TRAVERSAL] == 4
    # open redirect is probed on all query/form params — q, file, next = 3
    # (email is a json body param, not a navigation destination).
    assert ec[C.OPEN_REDIRECT] == 3
    # file upload only for the upload endpoint
    assert ec[C.FILE_UPLOAD] == 1
    # SQLi applies to all 4 injectable params
    assert ec[C.SQL_INJECTION] == 4
    # HPP only for query params (3)
    assert ec[C.HPP] == 3


def test_no_auth_surface_means_no_auth_plan():
    inv = _inv()  # no auth_routes set
    ec = eligible_counts(plan_tests(inv))
    assert ec[C.AUTH] == 0


def test_auth_surface_present_plans_auth():
    inv = _inv()
    inv.auth_routes = {"login_urls": ["https://t/login"], "session_cookie_names": ["sid"]}
    ec = eligible_counts(plan_tests(inv, auth_available=True))
    assert ec[C.AUTH] == 1


def test_security_misconfig_is_host_level_not_per_endpoint():
    inv = _inv()
    ec = eligible_counts(plan_tests(inv))
    assert ec[C.SECURITY_MISCONFIGURATION] == 1
    assert ec[C.SENSITIVE_INFO_DISCLOSURE] == 1
