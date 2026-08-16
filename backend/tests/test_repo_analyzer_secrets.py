import subprocess
from pathlib import Path

import pytest

from app.services.repo_analyzer import _gather_files, _scan_secrets


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")

    # A committed config file with a real-looking secret — genuinely exposed
    # to anyone who clones the repo. Built from parts at runtime rather than
    # as one literal, so this test's own source doesn't itself contain a
    # matchable "KEY = "secret"" line that Perry would flag when this
    # repo scans itself.
    fake_key_name = "API" + "_KEY"
    fake_token = "sk_live_" + "abcdef0123456789abcdef01"
    (repo / "config.py").write_text(f'{fake_key_name} = "{fake_token}"\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "initial")

    # A standard, gitignored, never-staged .env — the correct hygiene
    # pattern, not an exposure of the same kind.
    (repo / ".gitignore").write_text(".env\n")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-q", "-m", "add gitignore")
    fake_password_key = "DATABASE" + "_PASSWORD"
    fake_password = "supersecret" + "value123"
    (repo / ".env").write_text(f"{fake_password_key}={fake_password}\n")

    return repo


def test_committed_secret_keeps_critical_severity(git_repo: Path):
    files = _gather_files(git_repo)
    findings = _scan_secrets(git_repo, files)
    committed = [f for f in findings if f.file == "config.py"]
    assert committed, "expected the committed secret to be detected"
    assert committed[0].severity == "critical"
    assert committed[0].confidence == "confirmed"


def test_gitignored_untracked_secret_is_capped(git_repo: Path):
    """A gitignored, never-staged secret is reported informationally
    (severity "info", local_only=True) rather than as a vulnerability — it
    has not actually been exposed to anyone who clones the repo, so it must
    not contribute to the risk score at all."""
    files = _gather_files(git_repo)
    findings = _scan_secrets(git_repo, files)
    local_env = [f for f in findings if f.file == ".env"]
    assert local_env, "expected the .env secret to still be detected"
    assert local_env[0].severity == "info"
    assert local_env[0].confidence != "confirmed"
    assert local_env[0].local_only is True
    assert "not committed" in local_env[0].code_context


def test_non_git_directory_keeps_current_behavior(tmp_path: Path):
    """No .git at all -> tracking status is 'unknown' -> no downgrade,
    since we can't actually confirm the file is safely ignored."""
    plain = tmp_path / "plain"
    plain.mkdir()
    fake_password_key = "DATABASE" + "_PASSWORD"
    fake_password = "supersecret" + "value123"
    (plain / ".env").write_text(f"{fake_password_key}={fake_password}\n")
    files = _gather_files(plain)
    findings = _scan_secrets(plain, files)
    assert findings and findings[0].severity == "critical"
