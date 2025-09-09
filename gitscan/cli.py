import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


GITS_CAN_EMOJI_UNSAFE = "\u26a0\ufe0f"  # ⚠️
GITS_CAN_EMOJI_OK = "\u2705"  # ✅
GITS_CAN_EMOJI_INFO = "\ud83d\udcc4"  # 📄


@dataclass
class RepoState:
    repo_root: str
    branch: Optional[str]
    ahead: int
    behind: int
    staged_files: List[str]
    modified_files: List[str]
    untracked_files: List[str]
    tracked_files: List[str]
    rebase_in_progress: bool


def run_git(args: Sequence[str], cwd: Optional[str] = None, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=check,
    )


def ensure_git_repo() -> Tuple[str, bool]:
    # Returns (git_dir, is_repo)
    try:
        cp = run_git(["git", "rev-parse", "--git-dir"])
        if cp.returncode != 0:
            return ("", False)
        git_dir = cp.stdout.strip()
        return (git_dir, True)
    except Exception:
        return ("", False)


def get_repo_root() -> Optional[str]:
    cp = run_git(["git", "rev-parse", "--show-toplevel"])
    if cp.returncode != 0:
        return None
    return cp.stdout.strip()


def parse_branch_status() -> Tuple[Optional[str], int, int]:
    # Uses short status to parse ahead/behind
    cp = run_git(["git", "status", "-sb"])
    if cp.returncode != 0:
        return (None, 0, 0)
    first = cp.stdout.splitlines()[0] if cp.stdout else ""
    # Examples:
    # ## main...origin/main [ahead 2]
    # ## feature
    branch = None
    ahead = 0
    behind = 0
    if first.startswith("## "):
        first = first[3:]
        # Split by space to separate tracking info
        tokens = first.split()
        if tokens:
            branch = tokens[0].split("...")[0]
        m_ahead = re.search(r"\[ahead (\d+)\]", first)
        m_behind = re.search(r"\[behind (\d+)\]", first)
        if m_ahead:
            ahead = int(m_ahead.group(1))
        if m_behind:
            behind = int(m_behind.group(1))
    return (branch, ahead, behind)


def list_files(cmd: Sequence[str]) -> List[str]:
    cp = run_git(cmd)
    if cp.returncode != 0:
        return []
    return [l.strip() for l in cp.stdout.splitlines() if l.strip()]


def detect_rebase_in_progress(git_dir: str) -> bool:
    # rebase-apply or rebase-merge indicates rebase in progress
    try:
        return os.path.isdir(os.path.join(git_dir, "rebase-apply")) or os.path.isdir(
            os.path.join(git_dir, "rebase-merge")
        )
    except Exception:
        return False


def get_repo_state() -> Optional[RepoState]:
    root = get_repo_root()
    if not root:
        return None
    git_dir, ok = ensure_git_repo()
    if not ok:
        return None
    branch, ahead, behind = parse_branch_status()
    staged = list_files(["git", "diff", "--name-only", "--cached"])
    modified = list_files(["git", "diff", "--name-only"])
    untracked = list_files(["git", "ls-files", "--others", "--exclude-standard"])
    tracked = list_files(["git", "ls-files"])
    rebase = detect_rebase_in_progress(git_dir)
    return RepoState(
        repo_root=root,
        branch=branch,
        ahead=ahead,
        behind=behind,
        staged_files=staged,
        modified_files=modified,
        untracked_files=untracked,
        tracked_files=tracked,
        rebase_in_progress=rebase,
    )


# Junk patterns that should not be tracked
JUNK_PREFIXES: Tuple[str, ...] = (
    "node_modules/",
    "venv/",
    ".venv/",
    "__pycache__/",
    ".pytest_cache/",
)
JUNK_SUFFIXES: Tuple[str, ...] = (
    ".log",
    ".coverage",
    ".pyc",
    ".pyo",
    ".pyd",
)
JUNK_EXACT: Set[str] = {
    ".DS_Store",
}


SECRET_FILENAME_CUES: Tuple[str, ...] = (
    ".env",
    "id_rsa",
)
SECRET_SUFFIXES: Tuple[str, ...] = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
)


SECRET_REGEXES: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ),
    (
        "Slack Token",
        re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,48}"),
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    ),
    (
        "Generic Secret assignment",
        re.compile(r"(?i)(secret|password|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.+=]{20,}"),
    ),
]


def detect_tracked_junk(tracked_files: Iterable[str]) -> Dict[str, Set[str]]:
    # Returns {pattern: {files}}
    found: Dict[str, Set[str]] = {}
    for path in tracked_files:
        base = os.path.basename(path)
        if base in JUNK_EXACT:
            found.setdefault(base, set()).add(path)
        for pref in JUNK_PREFIXES:
            if path.startswith(pref):
                found.setdefault(pref + "*", set()).add(path)
        for suf in JUNK_SUFFIXES:
            if path.endswith(suf):
                found.setdefault("*" + suf, set()).add(path)
    return found


def git_show_staged(path: str) -> Optional[bytes]:
    cp = run_git(["git", "show", f":{path}"])
    if cp.returncode != 0:
        return None
    # Return raw bytes; subprocess was text=True, but decode back for null detection
    return cp.stdout.encode(errors="ignore")


def detect_secrets_in_staged(staged_files: Iterable[str]) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    for path in staged_files:
        lower = path.lower()
        base = os.path.basename(lower)
        if base in SECRET_FILENAME_CUES or base.startswith(".env"):
            issues.append((path, "Suspicious filename"))
            continue
        for suf in SECRET_SUFFIXES:
            if lower.endswith(suf):
                issues.append((path, f"File suffix suggests secret ({suf})"))
                break
        content = git_show_staged(path)
        if not content:
            continue
        if b"\x00" in content:
            # Probably binary; skip content regex
            continue
        text = content.decode(errors="ignore")
        for label, rx in SECRET_REGEXES:
            if rx.search(text):
                issues.append((path, label))
                break
    return issues


def dir_exists_in_repo_root(repo_root: str, dirname: str) -> bool:
    return os.path.isdir(os.path.join(repo_root, dirname))


def make_suggestions(state: RepoState, override_danger: bool) -> Tuple[List[str], List[str]]:
    issues: List[str] = []
    suggestions: List[str] = []

    # Rebase guardrail
    if state.rebase_in_progress:
        issues.append(f"{GITS_CAN_EMOJI_UNSAFE} Rebase in progress detected. Prefer merges over rebase.")
        suggestions.append("Use: git rebase --abort, then git pull or git merge to integrate changes.")

    # Force push guardrail
    if state.ahead > 0 and state.behind > 0:
        issues.append(f"{GITS_CAN_EMOJI_UNSAFE} Branch diverged (ahead {state.ahead}, behind {state.behind}). Never force push.")
        suggestions.append("Prefer: git pull to merge remote changes, then git push.")
    elif state.ahead > 0:
        # Friendly reminder even when only ahead
        suggestions.append("Avoid: git push -f. Use a regular git push.")

    # Avoid git add .
    if state.untracked_files or state.modified_files:
        issues.append(f"{GITS_CAN_EMOJI_UNSAFE} Avoid 'git add .'. It may stage junk or secrets.")
        add_alternatives: List[str] = ["git add -p"]
        if dir_exists_in_repo_root(state.repo_root, "src"):
            add_alternatives.append("git add src/")
        if dir_exists_in_repo_root(state.repo_root, "tests"):
            add_alternatives.append("git add tests/")
        suggestions.append("Prefer: " + ", ".join(add_alternatives))

    # Discourage stash
    if state.modified_files or state.untracked_files:
        suggestions.append(
            "Discouraged: git stash. Prefer saving work with a branch: git checkout -b <name>"
        )

    # .gitignore hygiene
    junk = detect_tracked_junk(state.tracked_files)
    if junk:
        issues.append(f"{GITS_CAN_EMOJI_UNSAFE} Tracked junk detected that should be in .gitignore.")
        add_lines = sorted(junk.keys())
        suggestions.append(
            "Add to .gitignore: " + ", ".join(add_lines)
        )

    # Secrets detection
    secret_hits = detect_secrets_in_staged(state.staged_files)
    if secret_hits:
        for path, label in secret_hits:
            issues.append(f"{GITS_CAN_EMOJI_UNSAFE} Potential secret in staged file: {path} ({label}).")
        if not override_danger:
            suggestions.append(
                "BLOCK: Unstage sensitive files and rotate credentials if leaked. Re-run with --i-know-what-im-doing to proceed at your own risk."
            )

    # Merge vs Rebase messaging
    suggestions.append("Prefer merges over rebase: use 'git pull' or 'git merge'.")

    # Final ok message if nothing risky
    if not issues:
        suggestions.append(f"{GITS_CAN_EMOJI_OK} No critical issues detected.")

    return issues, suggestions


def print_summary(state: RepoState, issues: List[str], suggestions: List[str]) -> None:
    print(f"Repository: {state.repo_root}")
    if state.branch:
        ahead_behind = []
        if state.ahead:
            ahead_behind.append(f"ahead {state.ahead}")
        if state.behind:
            ahead_behind.append(f"behind {state.behind}")
        ab = f" ({', '.join(ahead_behind)})" if ahead_behind else ""
        print(f"Branch: {state.branch}{ab}")
    print()
    if issues:
        print("Issues detected:")
        for msg in issues:
            print(f" - {msg}")
    else:
        print("No immediate issues detected.")
    print()
    print("Suggestions:")
    for s in suggestions:
        print(f" - {s}")


def interactive_show(state: RepoState, issues: List[str], suggestions: List[str]) -> None:
    print()
    print("Interactive mode (no commands will be executed):")
    print("Select suggestions to review. Run chosen commands manually in your shell.")
    print()
    for idx, s in enumerate(suggestions, start=1):
        print(f" [{idx}] {s}")
    print()
    print("Press Enter to exit.")
    try:
        _ = input("")
    except EOFError:
        pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gitscan",
        description=(
            "gitscan is an opinionated Git assistant that detects risky situations and suggests safe alternatives."
        ),
    )
    parser.add_argument(
        "--i-know-what-im-doing",
        dest="override",
        action="store_true",
        help="Acknowledge unsafe actions; lowers severity of some blocks.",
    )
    parser.add_argument(
        "--interactive",
        dest="interactive",
        action="store_true",
        help="Show an interactive (read-only) menu of suggestions.",
    )
    args = parser.parse_args(argv)

    git_dir, is_repo = ensure_git_repo()
    if not is_repo:
        print("Not a Git repository.")
        return 1

    state = get_repo_state()
    if state is None:
        print("Unable to determine Git repository state.")
        return 1

    issues, suggestions = make_suggestions(state, args.override)
    print_summary(state, issues, suggestions)

    if args.interactive and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        interactive_show(state, issues, suggestions)

    # Exit code policy:
    # - If secrets found and not overridden, return 2 (would block commit)
    # - Else 0
    secret_hits = detect_secrets_in_staged(state.staged_files)
    if secret_hits and not args.override:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())


