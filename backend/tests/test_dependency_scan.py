import logging
from pathlib import Path

import pytest

from app.services import repo_analyzer


async def test_malformed_package_json_logs_warning_instead_of_silent_pass(
    tmp_path: Path, caplog
):
    """A broken manifest must be distinguishable in logs from a genuinely
    dependency-free repo — previously a bare `except Exception: pass`
    swallowed the error with no trace."""
    (tmp_path / "package.json").write_text("{ this is not valid json")

    with caplog.at_level(logging.WARNING, logger="scanner.repo"):
        findings = await repo_analyzer._scan_dependencies(tmp_path, [])

    assert findings == []
    assert any("Could not parse" in r.message for r in caplog.records)


async def test_dependencies_and_dev_dependencies_are_both_queried(
    tmp_path: Path, monkeypatch
):
    """A package pinned to different versions in `dependencies` and
    `devDependencies` must not have one version silently dropped by
    `{**deps, **dev_deps}` collapsing the two into one dict entry."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"left-pad": "1.0.0"}, '
        '"devDependencies": {"left-pad": "2.0.0", "jest": "29.0.0"}}'
    )

    calls: list[tuple[str, dict]] = []

    async def fake_query_osv(ecosystem, deps, repo_path, files, declared):
        calls.append((ecosystem, dict(deps)))
        return []

    monkeypatch.setattr(repo_analyzer, "_query_osv", fake_query_osv)

    await repo_analyzer._scan_dependencies(tmp_path, [])

    all_queried_names = {name for _, deps in calls for name in deps}
    assert "jest" in all_queried_names
    assert "left-pad" in all_queried_names
    # left-pad must appear with its `dependencies`-section version (1.0.0),
    # not silently overwritten by the devDependencies entry.
    left_pad_versions = {deps["left-pad"] for _, deps in calls if "left-pad" in deps}
    assert "1.0.0" in left_pad_versions
