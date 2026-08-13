from app.cli import _validate_custom_tests, main


def test_invalid_custom_test_case_is_rejected_with_clear_error():
    cases, errors = _validate_custom_tests([{"name": "missing required fields"}])
    assert cases == []
    assert errors and "missing required fields" in errors[0]


def test_valid_custom_test_case_passes_validation():
    cases, errors = _validate_custom_tests([{
        "name": "Valid case", "path": "/x", "input": "id", "test": "1",
    }])
    assert errors == []
    assert len(cases) == 1
    assert cases[0].method == "GET"       # default applied
    assert cases[0].location == "query"   # default applied
    assert cases[0].expected == "differs"  # default applied


def test_non_interactive_without_tests_file_refuses(capsys, monkeypatch):
    """CI/CD has no TTY — must never block waiting for input, and must
    never proceed without an explicit test file."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code = main(["custom-test", "--url", "https://example.com"])
    assert code == 2
    assert "requires --tests" in capsys.readouterr().err


def test_non_interactive_without_authorized_refuses_even_with_tests(tmp_path, capsys, monkeypatch):
    """A supplied test file alone must never be enough to send live
    requests non-interactively — --authorized must also be explicit."""
    tests_file = tmp_path / "tests.json"
    tests_file.write_text(
        '[{"name": "t", "path": "/x", "input": "id", "test": "1"}]'
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code = main(["custom-test", "--url", "https://example.com", "--tests", str(tests_file)])
    assert code == 2
    assert "requires --authorized" in capsys.readouterr().err
