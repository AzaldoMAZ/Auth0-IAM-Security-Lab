"""
scan_secrets.py
Scans staged files for patterns that look like secrets or PII before a
commit is allowed to proceed. Built directly in response to real
incidents in this lab: an Auth0 client secret was pasted in plaintext
twice, a GitHub personal access token once, and raw logs containing a
real email address and Auth0 user ID were committed before being
caught manually. This script is the automated version of the manual
check that should have caught all three.

Usage:
    python scan_secrets.py            # scans currently staged files
    python scan_secrets.py file1 file2   # scans specific files

Exit code 0 = clean, safe to commit.
Exit code 1 = one or more findings; commit should be blocked.

IMPORTANT: this script never prints the actual matched secret. It
prints a masked preview only, so running the scanner cannot itself
leak a credential into your terminal history or CI logs.
"""

import re
import subprocess
import sys
from pathlib import Path

# (description, compiled pattern) -- patterns are intentionally specific
# enough to avoid flagging ordinary code, at the cost of not catching
# every possible secret format. A scanner with too many false positives
# gets disabled by frustrated developers, which defeats the purpose.
PATTERNS = [
    ("GitHub personal access token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "Non-empty secret/token/key assignment",
        re.compile(
            r"^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*\s*[:=]\s*"
            r"[\"']([A-Za-z0-9+/_\-\.]{16,})[\"']\s*[,;]?\s*$"
            r"|"
            r"^[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*=([A-Za-z0-9+/_\-\.]{16,})\s*$",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "Email address",
        re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+"),
    ),
]

# Placeholder values that should never be treated as real secrets.
PLACEHOLDER_RE = re.compile(
    r"^(your[-_]?|example|xxx+|changeme|placeholder|<.*>|\.\.\.|redacted)",
    re.IGNORECASE,
)

# Files where matches are expected and safe (templates, this script itself).
SKIP_FILENAMES = {".env.example", "scan_secrets.py"}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".lock"}


def mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def get_staged_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def should_skip(path: Path) -> bool:
    if path.name in SKIP_FILENAMES:
        return True
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    return False


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """Returns a list of (line_number, description, masked_preview)."""
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_no, line in enumerate(text.splitlines(), start=1):
        for description, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = None
            if match.groups():
                # Pick whichever alternation group actually captured.
                for group in match.groups():
                    if group:
                        value = group
                        break
            if value is None:
                value = match.group(0)
            if PLACEHOLDER_RE.match(value.strip()):
                continue
            findings.append((line_no, description, mask(value)))

    return findings


def main() -> int:
    targets = sys.argv[1:] if len(sys.argv) > 1 else get_staged_files()
    any_findings = False

    for file_str in targets:
        path = Path(file_str)
        if not path.exists() or should_skip(path):
            continue

        findings = scan_file(path)
        if findings:
            any_findings = True
            print(f"\n{path}:")
            for line_no, description, preview in findings:
                print(f"  line {line_no}: {description} -> {preview}")

    if any_findings:
        print(
            "\nCommit blocked: possible secret or PII detected above.\n"
            "Review the flagged lines. If this is a false positive, use a "
            "placeholder value (e.g. 'your-value-here') or rename the file "
            "to *.example. Never commit a real secret to work around this."
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())