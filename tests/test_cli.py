import builtins
import types
from gitscan import cli as gcli


def make_state(**kwargs):
    default = dict(
        repo_root="/tmp/repo",
        branch="main",
        ahead=0,
        behind=0,
        staged_files=[],
        modified_files=[],
        untracked_files=[],
        tracked_files=[],
        rebase_in_progress=False,
    )
    default.update(kwargs)
    return gcli.RepoState(**default)


def test_detect_tracked_junk():
    files = [
        ".DS_Store",
        "node_modules/lodash/index.js",
        "venv/bin/activate",
        "app/debug.log",
        "src/main.py",
    ]
    junk = gcli.detect_tracked_junk(files)
    keys = set(junk.keys())
    assert ".DS_Store" in keys
    assert "node_modules/*" in keys
    assert "venv/*" in keys
    assert "*.log" in keys


def test_secrets_detection_from_regex(monkeypatch):
    staged = ["config.py"]

    def fake_show(path):
        return b"API_KEY = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd'\n"

    monkeypatch.setattr(gcli, "git_show_staged", fake_show)
    hits = gcli.detect_secrets_in_staged(staged)
    assert hits and hits[0][0] == "config.py"


def test_make_suggestions_rebase_and_add_dot():
    state = make_state(
        rebase_in_progress=True,
        modified_files=["foo.txt"],
        untracked_files=["bar.txt"],
        tracked_files=[".DS_Store"],
    )
    issues, suggestions = gcli.make_suggestions(state, override_danger=False)
    joined = "\n".join(issues + suggestions)
    assert "Rebase in progress" in joined
    assert "Avoid 'git add .'" in joined
    assert ".gitignore" in joined


def test_main_not_git_repo(monkeypatch, capsys):
    monkeypatch.setattr(gcli, "ensure_git_repo", lambda: ("", False))
    code = gcli.main([])
    captured = capsys.readouterr()
    assert code == 1
    assert "Not a Git repository" in captured.out


def test_main_secrets_exit_code(monkeypatch):
    # Stub repo and state
    monkeypatch.setattr(gcli, "ensure_git_repo", lambda: (".git", True))
    state = make_state(staged_files=["secrets.env"]) 
    monkeypatch.setattr(gcli, "get_repo_state", lambda: state)
    monkeypatch.setattr(gcli, "detect_secrets_in_staged", lambda files: [("secrets.env", "Suspicious filename")])
    code = gcli.main([])
    assert code == 2


def test_interactive_flag_degrades_when_not_tty(monkeypatch, capsys):
    monkeypatch.setattr(gcli, "ensure_git_repo", lambda: (".git", True))
    state = make_state()
    monkeypatch.setattr(gcli, "get_repo_state", lambda: state)
    # Simulate non-tty
    class FakeStdin:
        def isatty(self):
            return False
    monkeypatch.setattr(gcli.sys, "stdin", FakeStdin())
    code = gcli.main(["--interactive"])  # should just print summary and exit 0
    assert code == 0


