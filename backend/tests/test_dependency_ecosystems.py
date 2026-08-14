"""
Dependency manifest parsing for the 6 new ecosystems (Go, RubyGems, Maven,
Packagist, crates.io, NuGet). The OSV.dev query path itself is unchanged and
untested here — only manifest reading and import-pattern matching, which is
where all the new logic actually lives.
"""
import asyncio
from pathlib import Path
from unittest.mock import patch

from app.services.dependency_analysis import _import_patterns, read_declared_dependencies


def test_go_mod_parsed_and_import_matches(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\ngo 1.21\n"
        "require (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
    )
    declared = read_declared_dependencies(tmp_path)
    assert declared[("Go", "github.com/gin-gonic/gin")] == (True, False)
    patterns = _import_patterns("github.com/gin-gonic/gin", "Go")
    assert any(p.search('import "github.com/gin-gonic/gin"') for p in patterns)


def test_gemfile_and_lock_parsed_and_import_matches(tmp_path):
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\ngem "rails"\n')
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    rails (7.0.0)\n")
    declared = read_declared_dependencies(tmp_path)
    assert ("RubyGems", "rails") in declared
    patterns = _import_patterns("rails", "RubyGems")
    assert any(p.search('require "rails"') for p in patterns)


def test_composer_json_parsed_and_import_matches(tmp_path):
    (tmp_path / "composer.json").write_text(
        '{"require": {"monolog/monolog": "^2.0", "php": ">=8.0"}}'
    )
    declared = read_declared_dependencies(tmp_path)
    assert ("Packagist", "monolog/monolog") in declared
    assert ("Packagist", "php") not in declared  # runtime, not a real package
    patterns = _import_patterns("monolog/monolog", "Packagist")
    assert any(p.search("use Monolog\\Logger;") for p in patterns)


def test_cargo_toml_parsed_and_import_matches(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "app"\n[dependencies]\nserde-json = "1.0"\n'
        '[dev-dependencies]\nmockall = "0.11"\n'
    )
    declared = read_declared_dependencies(tmp_path)
    assert declared[("crates.io", "serde-json")] == (True, False)
    assert declared[("crates.io", "mockall")] == (True, True)
    patterns = _import_patterns("serde-json", "crates.io")
    assert any(p.search("use serde_json::Value;") for p in patterns)


def test_pom_xml_parsed_and_scope_detected(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies>"
        "<dependency><groupId>org.apache.commons</groupId>"
        "<artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency>"
        "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
        "<version>4.13</version><scope>test</scope></dependency>"
        "</dependencies></project>"
    )
    declared = read_declared_dependencies(tmp_path)
    assert declared[("Maven", "commons-lang3")] == (True, False)
    assert declared[("Maven", "junit")] == (True, True)


def test_csproj_parsed(tmp_path):
    (tmp_path / "A.csproj").write_text(
        '<Project><ItemGroup>'
        '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />'
        '</ItemGroup></Project>'
    )
    declared = read_declared_dependencies(tmp_path)
    assert declared[("NuGet", "Newtonsoft.Json")] == (True, False)
    patterns = _import_patterns("Newtonsoft.Json", "NuGet")
    assert any(p.search("using Newtonsoft.Json;") for p in patterns)


def test_scan_dependencies_dispatches_each_new_manifest(tmp_path):
    """End-to-end: _scan_dependencies extracts the right (ecosystem, deps)
    pairs from a repo with all 6 new manifest types, without hitting OSV."""
    import app.services.repo_analyzer as ra

    (tmp_path / "go.mod").write_text("module x\nrequire github.com/lib/pq v1.10.9\n")
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    pg (1.4.0)\n")
    (tmp_path / "composer.json").write_text('{"require": {"guzzlehttp/guzzle": "7.0.0"}}')
    (tmp_path / "Cargo.toml").write_text('[package]\nname="a"\n[dependencies]\ntokio = "1.0"\n')
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>commons-io</artifactId>"
        "<version>2.11.0</version></dependency></dependencies></project>"
    )
    (tmp_path / "A.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup></Project>'
    )

    calls = []

    async def fake_query_osv(ecosystem, deps, repo_path, files, declared):
        calls.append((ecosystem, dict(deps)))
        return []

    with patch.object(ra, "_query_osv", fake_query_osv):
        asyncio.run(ra._scan_dependencies(tmp_path, list(tmp_path.iterdir())))

    seen = dict(calls)
    assert seen["Go"] == {"github.com/lib/pq": "v1.10.9"}
    assert seen["RubyGems"] == {"pg": "1.4.0"}
    assert seen["Packagist"] == {"guzzlehttp/guzzle": "7.0.0"}
    assert seen["crates.io"] == {"tokio": "1.0"}
    assert seen["Maven"] == {"commons-io": "2.11.0"}
    assert seen["NuGet"] == {"Serilog": "2.10.0"}
