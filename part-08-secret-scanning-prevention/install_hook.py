"""
install_hook.py
Installs scan_secrets.py as a git pre-commit hook for this repository.
Run this once per clone -- git hooks live in .git/hooks/, which is not
tracked by git itself, so every contributor needs to run this after
cloning for the protection to be active on their machine.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path

HOOK_CONTENT = """#!/bin/sh
# Installed by part-08-secret-scanning-prevention/install_hook.py
# Blocks a commit if scan_secrets.py finds a likely secret or PII.

REPO_ROOT="$(git rev-parse --show-toplevel)"
python "$REPO_ROOT/part-08-secret-scanning-prevention/scan_secrets.py"
exit $?
"""


def main() -> int:
    try:
        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Could not find a git repository. Run this from inside your repo.")
        return 1

    hooks_dir = Path(repo_root) / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    hook_path.write_text(HOOK_CONTENT, encoding="utf-8", newline="\n")

    try:
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass  # Windows: executable bit is not required for Git Bash to run it.

    print(f"Pre-commit secret scanner installed -> {hook_path}")
    print("Every future 'git commit' in this repo will now be scanned first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())