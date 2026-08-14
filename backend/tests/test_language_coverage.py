"""
Language coverage reporting — the direct fix for a scan silently claiming
"0 findings" for a language it never actually analyzed.
"""
import asyncio

from app.services.sast_engine import analyze_sources, compute_language_coverage
from app.cli import scan_path


def test_coverage_reports_files_found_and_analyzed(tmp_path):
    (tmp_path / "a.py").write_text("import os\n")
    (tmp_path / "b.go").write_text("package main\n")
    (tmp_path / "c.txt").write_text("not code\n")

    files = list(tmp_path.iterdir())
    cov = compute_language_coverage(tmp_path, files)

    assert cov["Python"]["files_found"] == 1
    assert cov["Python"]["files_analyzed"] == 1
    assert cov["Go"]["files_found"] == 1
    assert cov["Go"]["files_analyzed"] == 1
    assert "c.txt" not in str(cov)  # non-code extension isn't tracked at all


def test_coverage_reports_skip_reason_when_tree_sitter_unavailable(tmp_path, monkeypatch):
    import app.services.polyglot_sast as polyglot_sast
    monkeypatch.setattr(polyglot_sast, "_TS_AVAILABLE", False)

    (tmp_path / "a.go").write_text("package main\n")
    files = list(tmp_path.iterdir())
    cov = compute_language_coverage(tmp_path, files)

    assert cov["Go"]["files_found"] == 1
    assert cov["Go"]["files_analyzed"] == 0
    assert cov["Go"]["files_skipped"] == 1
    assert cov["Go"]["skip_reason"] == "tree-sitter not installed"


def test_analyze_sources_degrades_without_crashing_when_tree_sitter_unavailable(tmp_path, monkeypatch):
    import app.services.polyglot_sast as polyglot_sast
    monkeypatch.setattr(polyglot_sast, "_TS_AVAILABLE", False)

    (tmp_path / "a.py").write_text('import os\nos.system(request.args.get("x"))\n')
    (tmp_path / "b.go").write_text('package main\nfunc f(r *http.Request) { exec.Command(r.FormValue("x")) }\n')

    findings = analyze_sources(tmp_path, list(tmp_path.iterdir()))
    # Python still works even though Go's SAST is unavailable.
    assert any(f.file == "a.py" for f in findings)
    assert not any(f.file == "b.go" for f in findings)


def test_cli_scan_path_includes_languages_key(tmp_path):
    (tmp_path / "a.py").write_text("import os\n")
    (tmp_path / "b.rb").write_text("x = params[:x]\nsystem(x)\n")

    result = asyncio.run(scan_path(tmp_path, skip_deps=True))
    assert "languages" in result
    assert "Python" in result["languages"]
    assert "Ruby" in result["languages"]
    assert any("command" in f["title"].lower() for f in result["findings"])
