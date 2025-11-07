#!/usr/bin/env python3
"""
process_clean_recursive.py
Recursively cleans Sigma YAML rules and safely pushes to GitHub (origin/main).
"""

import os
import re
import subprocess
from datetime import datetime

ROOT_DIR = os.getcwd()

# Patterns
RE_DELETE_RE = re.compile(r"\|\s*re\b", re.IGNORECASE)
RE_RELATED_BLOCK = re.compile(r"(?ms)^[ \t]*related:\s*\n(?:^[ \t].*\n)*")
RE_NULL = re.compile(r":\s*null\b")
KEYWORD_PATTERNS = [
    re.compile(r"\|\s*windash\b", re.IGNORECASE),
    re.compile(r"\|\s*base64offset\b", re.IGNORECASE),
    re.compile(r"\|\s*base64\b", re.IGNORECASE),
    re.compile(r"\|\s*cidr\b", re.IGNORECASE),
]
YAML_EXT = (".yml", ".yaml")

deleted, cleaned, skipped, empty_deleted = [], [], [], []


def run_git(args, capture=False):
    return subprocess.run(["git"] + args, cwd=ROOT_DIR, text=True,
                          capture_output=capture, shell=False)


def clean_file(path):
    """Clean one YAML file based on Sigma cleanup rules."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        skipped.append((path, str(e)))
        return

    # Delete if |re found
    if RE_DELETE_RE.search(content):
        os.remove(path)
        deleted.append(path)
        print(f"🗑️ Deleted (|re): {path}")
        return

    original = content
    for pat in KEYWORD_PATTERNS:
        content = pat.sub("", content)
    content = RE_RELATED_BLOCK.sub("", content)
    content = RE_NULL.sub(": 'null'", content)

    if content.strip() == "":
        os.remove(path)
        empty_deleted.append(path)
        print(f"🗑️ Deleted (empty): {path}")
        return

    if content != original:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        cleaned.append(path)
        print(f"🧹 Cleaned: {path}")


def walk_and_clean(root):
    for dirpath, _, files in os.walk(root):
        if ".git" in dirpath:
            continue
        for fn in files:
            if fn.lower().endswith(YAML_EXT):
                clean_file(os.path.join(dirpath, fn))


def ensure_branch_main():
    """Ensure we're on a proper branch (main), not detached HEAD."""
    res = run_git(["rev-parse", "--abbrev-ref", "HEAD"], capture=True)
    if "HEAD" in res.stdout:
        print("⚠️ Detached HEAD detected. Reattaching to 'main'.")
        run_git(["checkout", "-B", "main"])
    else:
        branch = res.stdout.strip()
        if branch != "main":
            print(f"🔀 Switching to main (current: {branch})")
            run_git(["checkout", "main"])


def git_changes_exist():
    res = run_git(["status", "--porcelain"], capture=True)
    return bool(res.stdout.strip())


def commit_and_push():
    """Commit and force-push to origin/main safely."""
    if not git_changes_exist():
        print("✅ No git changes detected.")
        return

    run_git(["add", "-A"])
    msg = f"Auto-clean: removed |re rules, keywords, related, and fixed nulls ({datetime.utcnow().isoformat()}Z)"
    run_git(["commit", "-m", msg])
    run_git(["fetch", "origin"])
    print("🚀 Pushing to origin/main...")
    push = run_git(["push", "origin", "HEAD:main", "--force"], capture=True)

    if push.returncode == 0:
        print("✅ Push completed successfully.")
    else:
        print("❌ Push failed:")
        print(push.stdout)
        print(push.stderr)


def main():
    print(f"🔎 Starting recursive cleanup in: {ROOT_DIR}")
    ensure_branch_main()
    walk_and_clean(ROOT_DIR)
    print(f"Summary: {len(deleted)} deleted, {len(empty_deleted)} empty removed, {len(cleaned)} cleaned.")
    commit_and_push()


if __name__ == "__main__":
    main()
