from app.cli import _parse_kv_line, _spec_from_shorthand, _validate_preset_specs


def test_parse_kv_line_accepts_equals_colon_and_dash_separators():
    parsed = _parse_kv_line("attack=sql injection, path: /login, name-kabir")
    assert parsed == {"attack": "sql injection", "path": "/login", "name": "kabir"}


def test_parse_kv_line_keeps_dashes_inside_values():
    parsed = _parse_kv_line("path-/login-page")
    assert parsed == {"path": "/login-page"}


def test_attack_key_routes_to_preset_shape():
    kind, spec = _spec_from_shorthand({"attack": "sql injection", "path": "/x"})
    assert kind == "preset"
    assert spec["attack"] == "sql injection"


def test_no_attack_key_routes_to_strict_shape():
    kind, spec = _spec_from_shorthand({"path": "/x", "input": "id", "test": "1"})
    assert kind == "strict"
    assert spec["input"] == "id"


def test_name_field_is_never_swallowed_as_the_test_title():
    """Regression: 'name' is exactly as likely to be a real form field (a
    login form's username input) as it is to mean "the test's own title" —
    a preset spec must treat it as a request field, not consume it."""
    kind, spec = _spec_from_shorthand({
        "attack": "sql injection", "path": "/login", "name": "kabir", "password": "1234",
    })
    assert kind == "preset"
    assert spec["fields"] == {"name": "kabir", "password": "1234"}
    assert "kabir" not in spec["name"]  # the auto-generated title, not the field value


def test_get_is_the_default_method_even_when_fields_are_given():
    """Regression: defaulting to POST whenever fields exist guessed wrong
    for GET-based endpoints that take data via the query string (e.g.
    ?id=), which is the more common case this shorthand targets."""
    _, spec = _spec_from_shorthand({"attack": "sqli", "path": "/products", "id": "1"})
    assert spec["method"] == "GET"
    assert spec["location"] == "query"


def test_explicit_method_post_defaults_location_to_form():
    _, spec = _spec_from_shorthand({
        "attack": "sqli", "path": "/login", "method": "POST", "name": "a", "password": "b",
    })
    assert spec["method"] == "POST"
    assert spec["location"] == "form"


def test_target_field_narrows_injection_to_one_field():
    _, spec = _spec_from_shorthand({
        "attack": "sqli", "path": "/products", "target": "id", "id": "1", "extra": "2",
    })
    assert spec["target"] == "id"
    assert spec["fields"] == {"id": "1", "extra": "2"}


def test_unknown_attack_name_is_rejected_with_known_names_listed():
    _, spec = _spec_from_shorthand({"attack": "made_up_attack", "path": "/x"})
    validated, errors = _validate_preset_specs([spec])
    assert validated == []
    assert errors and "made_up_attack" in errors[0]


def test_missing_path_is_rejected():
    _, spec = _spec_from_shorthand({"attack": "sqli"})
    validated, errors = _validate_preset_specs([spec])
    assert validated == []
    assert errors and "path" in errors[0]
