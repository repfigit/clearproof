"""The daily sanctions workflow must see a rebuilt tree even though artifacts/ is ignored."""

import json
import runpy
import subprocess
import sys

import pytest

from scripts import sanctions_tree_diff as diff


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=repo, check=True)


def write(repo, path, root, count, **extra):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"root": root, "leaf_count": count, **extra}))


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("artifacts/\n")
    git(tmp_path, "add", ".gitignore")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def commit_trees(repo):
    # The workflow force-adds the reviewed trees past the artifacts/ ignore rule.
    git(repo, "add", "-f", diff.LEGACY_TREE, diff.PILOT_TREE)
    git(repo, "commit", "-q", "-m", "trees")


def test_first_publication_is_a_change_despite_ignore_rule(repo):
    write(repo, diff.LEGACY_TREE, "11", 40)
    write(repo, diff.PILOT_TREE, 22, 42)
    # The defect being fixed: git reports nothing for an ignored, untracked file.
    assert subprocess.run(["git", "diff", "--quiet", diff.LEGACY_TREE], cwd=repo).returncode == 0
    assert diff.compare(repo, "HEAD") == {
        "changed": "true",
        "legacy_changed": "true",
        "pilot_changed": "true",
        "prev_count": "0",
        "new_count": "40",
        "pilot_prev_count": "0",
        "pilot_new_count": "42",
    }


def test_same_roots_with_new_timestamp_are_unchanged(repo):
    write(repo, diff.LEGACY_TREE, "11", 40, fetch_timestamp="day-1")
    write(repo, diff.PILOT_TREE, 22, 42, built_at="day-1")
    commit_trees(repo)
    write(repo, diff.LEGACY_TREE, "11", 40, fetch_timestamp="day-2")
    write(repo, diff.PILOT_TREE, 22, 42, built_at="day-2")
    outputs = diff.compare(repo, "HEAD")
    assert outputs["changed"] == "false"
    assert outputs["prev_count"] == outputs["new_count"] == "40"


@pytest.mark.parametrize(
    "legacy_root,pilot_root,legacy,pilot",
    [("12", 22, "true", "false"), ("11", 23, "false", "true"), ("12", 23, "true", "true")],
)
def test_either_root_change_opens_a_review(repo, legacy_root, pilot_root, legacy, pilot):
    write(repo, diff.LEGACY_TREE, "11", 40)
    write(repo, diff.PILOT_TREE, 22, 42)
    commit_trees(repo)
    write(repo, diff.LEGACY_TREE, legacy_root, 41)
    write(repo, diff.PILOT_TREE, pilot_root, 43)
    outputs = diff.compare(repo, "HEAD")
    assert (outputs["changed"], outputs["legacy_changed"], outputs["pilot_changed"]) == ("true", legacy, pilot)
    assert (outputs["prev_count"], outputs["new_count"]) == ("40", "41")
    assert (outputs["pilot_prev_count"], outputs["pilot_new_count"]) == ("42", "43")


@pytest.mark.parametrize("new_count,allowed", [(20, True), (19, False), (0, False)])
def test_leaf_count_floor(repo, new_count, allowed):
    write(repo, diff.LEGACY_TREE, "11", 40)
    write(repo, diff.PILOT_TREE, 22, 42)
    commit_trees(repo)
    write(repo, diff.LEGACY_TREE, "12", new_count)
    if allowed:
        assert diff.compare(repo, "HEAD")["changed"] == "true"
    else:
        with pytest.raises(diff.TreeDiffError):
            diff.compare(repo, "HEAD")


def test_empty_first_tree_is_refused(repo):
    write(repo, diff.LEGACY_TREE, "11", 0)
    write(repo, diff.PILOT_TREE, 22, 2)
    with pytest.raises(diff.TreeDiffError, match="no leaves"):
        diff.compare(repo, "HEAD")


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"leaf_count": 3}',
        '{"root": "", "leaf_count": 3}',
        '{"root": "1"}',
        '{"root": "1", "leaf_count": true}',
    ],
)
def test_malformed_or_missing_built_tree_stops_the_workflow(repo, content):
    write(repo, diff.PILOT_TREE, 22, 42)
    with pytest.raises(diff.TreeDiffError, match="not built"):
        diff.compare(repo, "HEAD")
    (repo / diff.LEGACY_TREE).write_text(content)
    with pytest.raises(diff.TreeDiffError):
        diff.compare(repo, "HEAD")


def test_malformed_committed_tree_stops_the_workflow(repo):
    write(repo, diff.PILOT_TREE, 22, 42)
    (repo / diff.LEGACY_TREE).write_text("not json")
    commit_trees(repo)
    write(repo, diff.LEGACY_TREE, "11", 40)
    with pytest.raises(diff.TreeDiffError, match="invalid JSON"):
        diff.compare(repo, "HEAD")


def test_cli_writes_github_outputs_and_reports_failure(repo, tmp_path, capsys):
    write(repo, diff.LEGACY_TREE, "11", 40)
    write(repo, diff.PILOT_TREE, 22, 42)
    output = tmp_path / "out.txt"
    assert diff.main(["--repo", str(repo), "--github-output", str(output)]) == 0
    assert "changed=true" in output.read_text().splitlines()
    assert "new_count=40" in capsys.readouterr().out

    write(repo, diff.LEGACY_TREE, "11", 0)
    assert diff.main(["--repo", str(repo)]) == 1
    assert "::error::" in capsys.readouterr().err


def test_cli_prints_outputs_without_github_output(repo, capsys):
    write(repo, diff.LEGACY_TREE, "11", 40)
    write(repo, diff.PILOT_TREE, 22, 42)
    assert diff.main(["--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "changed=true" in out
    assert "new_count=40" in out


def test_cli_entry_reports_the_leaf_floor_failure(repo, monkeypatch):
    write(repo, diff.LEGACY_TREE, "11", 0)
    write(repo, diff.PILOT_TREE, 22, 2)
    monkeypatch.setattr(sys, "argv", [diff.__file__, "--repo", str(repo)])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(diff.__file__, run_name="__main__")
    assert exit_info.value.code == 1
