"""Run scripts/check_dco.sh against throwaway git repositories."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_dco.sh"

pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None, reason="needs git+bash")


def _git(repo: Path, *args: str, author: str = "Dev Example", email: str = "dev@example.com") -> str:
    env = {
        "GIT_AUTHOR_NAME": author,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": author,
        "GIT_COMMITTER_EMAIL": email,
        "HOME": str(repo),
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "base")
    return tmp_path


def _check(repo: Path, base: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), base, "HEAD"], cwd=repo, capture_output=True, text=True)


def test_signed_commits_pass(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-s", "-m", "feat: signed")
    result = _check(repo, base)
    assert result.returncode == 0, result.stdout
    assert "1 commit(s) signed off" in result.stdout


def test_unsigned_commit_fails(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-s", "-m", "feat: signed")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "fix: unsigned")
    result = _check(repo, base)
    assert result.returncode == 1
    assert "fix: unsigned" in result.stdout and "::error::" in result.stdout


def test_signoff_must_match_author(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(
        repo,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "feat: someone else signed\n\nSigned-off-by: Other <other@example.com>",
    )
    assert _check(repo, base).returncode == 1


def test_signoff_email_is_case_insensitive(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "feat: x\n\nSigned-off-by: Dev <DEV@Example.com>")
    assert _check(repo, base).returncode == 0


def test_bot_authors_are_exempt(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "chore(deps): bump", author="dependabot[bot]", email="bot@x")
    result = _check(repo, base)
    assert result.returncode == 0
    assert "(bot)" in result.stdout


def test_merge_commits_are_skipped(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "side")
    _git(repo, "commit", "-q", "--allow-empty", "-s", "-m", "feat: side")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "commit", "-q", "--allow-empty", "-s", "-m", "feat: main")
    _git(repo, "merge", "-q", "--no-ff", "--no-edit", "side")
    result = _check(repo, base)
    assert result.returncode == 0
    assert "2 commit(s) signed off" in result.stdout
