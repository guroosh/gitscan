# gitscan

Opinionated Git assistant that detects risky situations and suggests safe alternatives.

## Installation

Once published to PyPI:

```bash
pip install gitscan
```

From source (for development):

```bash
pip install -e .
```

## Usage

```bash
gitscan [--i-know-what-im-doing]
```

What it does today:
- Detects repo state (staged/modified/untracked, branch ahead/behind)
- Guardrails:
  - ⚠️ Never `git add .` — suggests `git add -p` or scoping to `src/` / `tests/`
  - ⚠️ Never force push — avoid `git push -f`, prefer regular pushes and merges
  - ⚠️ Never rebase — detects rebase in progress, suggests merges instead
  - ⚠️ Discourages `git stash` — suggests branching instead
  - ✅ `.gitignore` hygiene — detects tracked junk (e.g., `.DS_Store`, `node_modules/`, `venv/`, `*.log`)
  - ✅ Secrets detection — scans staged files for likely secrets and blocks (exit 2) unless overridden

The CLI prints a summary of issues and safer suggestions. It does not run Git commands.

## Exit Codes
- 0: No critical blocks
- 1: Not a Git repo or failed to detect state
- 2: Potential secrets found in staged files (unless `--i-know-what-im-doing`)

## License
MIT
