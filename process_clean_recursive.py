#!/usr/bin/env python3
"""
process_clean_recursive.py

Recursively clean Sigma YAML rules:
 - Delete files containing |re (case-insensitive)
 - Remove keywords: |windash, |base64offset, |base64, |cidr
 - Remove `related:` blocks and their indented lines
 - Replace ": null" with ": 'null'"
 - Delete files that become empty
 - Commit & push safely to GitHub (tries current branch, then main/master, falls back to force)
"""

import os
import re
import subprocess
from datetime import datetime

# ---- Config ----
# If you prefer to hardcode repo path, change this. Otherwise run script from repo root.
ROOT_DIR = os.getcwd()
KEYWORD_PATTERNS = [
    re.compile(r"\|\s*windash\b", re.IGNORECASE),
    re.compile(r"\|\s*base64offset\b", re.IGNORECASE),
    re.compile(r"\|\s*base64\b", re.IGNORECASE),
    re.compile(r"\|\s*cidr\b", re.IGNORECASE),
]
RE_DELETE_RE = re.compile(r"\|\s*re\b", re.IGNORECASE)           # if matched -> delete whole file
RE_RELATED_BLOCK = re.compile(r"(?ms)^[ \t]*related:\s*\n(?:^[ \t].*\n)*")  # remove related: block and indented children
RE_NULL = re.compile(r":\s*null\b")                              # replace with : 'null'
YAML_EXT = (".yml", ".yaml")

# ---- State counters ----
deleted_files = []
cleaned_files = []
skipped_files = []
empty_deleted = []

def run_git(cmd_args, cwd=ROOT_DIR, capture=False):
    """Run git command, return CompletedProcess."""
    if capture:
        return subprocess.run(["git"] + cmd_args, cwd=cwd, capture_output=True, text=True)
    else:
        return subprocess.run(["git"] + cmd_args, cwd=cwd)

def file_changed_content(path, new_content):
    """Return True if the new_content is different from existing file (or file missing)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            old = f.read()
    except FileNotFoundError:
        return True
    return old != new_content

def clean_file(path):
    """Apply rules to a single file. Return: 'deleted'|'cleaned'|'untouched'|'empty_deleted'."""
    global deleted_files, cleaned_files, empty_deleted

    # read file
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception as e:
        skipped_files.append((path, f"read_error:{e}"))
        return "skipped"

    # 1) If contains |re -> delete file entirely
    if RE_DELETE_RE.search(content):
        try:
            os.remove(path)
            deleted_files.append(path)
            print(f"🗑️ Deleted (|re found): {path}")
            return "deleted"
        except Exception as e:
            skipped_files.append((path, f"delete_error:{e}"))
            return "skipped"

    original = content

    # 2) Remove keyword patterns like |windash, |base64offset, |base64, |cidr
    for pat in KEYWORD_PATTERNS:
        content = pat.sub("", content)

    # 3) Remove related: blocks with their indented children
    content = RE_RELATED_BLOCK.sub("", content)

    # 4) Replace ": null" -> ": 'null'"
    content = RE_NULL.sub(": 'null'", content)

    # Normalize multiple '||' occurrences caused by removals to single '|'
    content = re.sub(r"\|\|+", "|", content)

    # Trim trailing spaces at line ends but preserve indentation/newlines
    # (optional) we keep as is

    # If content becomes empty/only whitespace -> delete file
    if content.strip() == "":
        try:
            os.remove(path)
            empty_deleted.append(path)
            print(f"🗑️ Deleted (empty after cleaning): {path}")
            return "empty_deleted"
        except Exception as e:
            skipped_files.append((path, f"delete_empty_error:{e}"))
            return "skipped"

    # Write only if changed
    if content != original:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            cleaned_files.append(path)
            print(f"🧹 Cleaned: {path}")
            return "cleaned"
        except Exception as e:
            skipped_files.append((path, f"write_error:{e}"))
            return "skipped"

    return "untouched"

def walk_and_clean(root_dir):
    """Recursively walk and clean YAML files."""
    for dirpath, _, filenames in os.walk(root_dir):
        # skip .git directory
        if ".git" in dirpath.split(os.sep):
            continue
        for fname in filenames:
            if fname.lower().endswith(YAML_EXT):
                fpath = os.path.join(dirpath, fname)
                clean_file(fpath)

def git_changes_present():
    """Return True if there are changes to commit (git status --porcelain not empty)."""
    res = run_git(["status", "--porcelain"], capture=True)
    if res and res.stdout:
        return bool(res.stdout.strip())
    return False

def safe_commit_and_push():
    """Commit and push changes safely:
       - commit only if changes present
       - determine current branch
       - try push to current branch
       - fallback to HEAD:main and HEAD:master
       - fallback to force push if necessary
    """
    if not git_changes_present():
        print("✅ No git changes to commit or push.")
        return

    # stage changes
    run_git(["add", "-A"])
    commit_msg = f"Auto-clean recursive: removed |re rules, removed keywords, related blocks, normalized nulls ({datetime.utcnow().isoformat()}Z)"
    run_git(["commit", "-m", commit_msg])

    # detect branch
    res = run_git(["rev-parse", "--abbrev-ref", "HEAD"], capture=True)
    current_branch = "main"
    if res and res.stdout:
        current_branch = res.stdout.strip()
    print(f"🔀 Current branch detected: {current_branch}")

    # fetch remote
    run_git(["fetch", "origin"])

    # try pushing directly to current branch
    attempts = []
    pushed = False

    # list of branches to attempt: prefer current, then main, then master
    target_branches = [current_branch]
    if "main" not in target_branches:
        target_branches.append("main")
    if "master" not in target_branches:
        target_branches.append("master")

    for branch in target_branches:
        print(f"🌐 Attempting normal push to {branch}...")
        result = run_git(["push", "origin", f"HEAD:{branch}"], capture=True)
        attempts.append((branch, result))
        if result and result.returncode == 0:
            print(f"✅ Successfully pushed to origin/{branch}.")
            pushed = True
            break

    if not pushed:
        print("⚠️ Normal push failed for all targets. Attempting force push (last-resort)...")
        for branch in target_branches:
            print(f"🚨 Force-pushing to {branch}...")
            result = run_git(["push", "origin", f"HEAD:{branch}", "--force"], capture=True)
            attempts.append((f"{branch} (force)", result))
            if result and result.returncode == 0:
                print(f"🚀 Force-pushed to origin/{branch}.")
                pushed = True
                break

    if not pushed:
        print("❌ Push failed. Review the last git output below:")
        for b, res in attempts:
            if res:
                print(f"--- {b} ---")
                print(res.stdout or "")
                print(res.stderr or "")
    else:
        print("🎯 All done — changes pushed to GitHub.")

def main():
    print(f"🔎 Starting cleanup from: {ROOT_DIR}")
    walk_and_clean(ROOT_DIR)
    print()
    print(f"Summary: deleted {len(deleted_files)+len(empty_deleted)} files, cleaned {len(cleaned_files)} files, skipped {len(skipped_files)} files.")
    if skipped_files:
        print("Some files were skipped due to errors; see the printed messages above.")
    safe_commit_and_push()

if __name__ == "__main__":
    main()
