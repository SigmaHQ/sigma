#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates a machine-readable changelog for a Sigma release.

The changelog is a JSON document keyed by rule UUID (the rule `id` field),
describing which rules were added, updated, deprecated or removed between two
release tags. It is meant to complement the human-readable release notes by
giving users a stable, scriptable way to reconcile their local rule library
against upstream releases (e.g. via the pySigma framework).

The data is derived from the git diff between the two tags and the YAML
metadata of each changed rule, NOT from commit messages, so it is immune to
rule renames/moves (the UUID is the stable identifier).

EXAMPLE
# python3 tests/sigma-changelog.py --from r2025-12-01 --to r2026-01-01 --outfile changelog.json

If --from / --to are omitted, the two most recent release tags (matching the
`r*` pattern, e.g. `r2024-12-19`) are used automatically.
"""

import re
import sys
import json
import argparse
import subprocess

import yaml

# Top-level directories that hold canonical Sigma rules. The `deprecated` and
# `unsupported` lifecycle directories are included so that rules moving out of
# the active set are captured as end-of-life transitions rather than as
# removals. Non-rule trees (regression_data, splunk, sigma-cli, other) are
# intentionally excluded.
RULE_DIRS = [
    "rules",
    "rules-compliance",
    "rules-dfir",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "deprecated",
    "unsupported",
]

# Statuses that take a rule out of the actively-maintained set. Transitioning
# into one of these is reported as its own change type.
END_OF_LIFE_STATUS = {"deprecated", "unsupported"}

CHANGE_TYPE_ORDER = ["new", "update", "deprecated", "unsupported", "removed"]

# GitHub noreply emails embed the account handle, e.g.
# "24633258+st0pp3r@users.noreply.github.com" -> "st0pp3r".
NOREPLY_RE = re.compile(r"(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com")
COAUTHOR_RE = re.compile(r"Co-authored-by:\s*(.+?)\s*<([^>]+)>", re.IGNORECASE)
BOT_AUTHORS = {"copilot", "github-actions[bot]", "dependabot[bot]", "web-flow"}


def git(*args: str) -> str:
    """Run a git command in the repository root and return its stdout."""
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def latest_release_tags() -> tuple:
    """Return the (previous, current) release tags ordered by creation date.

    Mirrors the tag selection used in .github/workflows/release.yml.
    """
    out = git(
        "for-each-ref",
        "--sort=creatordate",
        "--format=%(refname:lstrip=2)",
        "refs/tags",
    )
    release_tags = [t for t in out.splitlines() if t.startswith("r")]
    if len(release_tags) < 2:
        print("[E] Need at least two release tags to build a changelog.")
        sys.exit(1)
    return release_tags[-2], release_tags[-1]


def init_arguments(arguments: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-f",
        "--from",
        dest="from_tag",
        help="Previous release tag (defaults to the second-newest r* tag)",
    )
    parser.add_argument(
        "-t",
        "--to",
        dest="to_tag",
        help="Current release tag (defaults to the newest r* tag)",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        default="changelog.json",
        help="Output JSON file (default: changelog.json)",
    )
    args = parser.parse_args(arguments)

    if not args.outfile.endswith(".json"):
        args.outfile = args.outfile + ".json"

    if not args.from_tag or not args.to_tag:
        prev_tag, curr_tag = latest_release_tags()
        args.from_tag = args.from_tag or prev_tag
        args.to_tag = args.to_tag or curr_tag
        print(
            "[I] Using release tags {} -> {}".format(args.from_tag, args.to_tag)
        )

    return args


def is_rule_path(path: str) -> bool:
    return path.endswith(".yml") and any(
        path == d or path.startswith(d + "/") for d in RULE_DIRS
    )


def parse_diff(from_tag: str, to_tag: str) -> list:
    """Return changed rule files as (status, old_path, new_path, score) tuples.

    `status` is a single letter (A/M/D/R/C). For renames/copies `score` holds
    the git similarity index (0-100); 100 means an identical, content-less move.
    The NUL-delimited format is used so paths containing spaces are safe.
    """
    raw = git(
        "diff",
        "--name-status",
        "-M",
        "-z",
        from_tag,
        to_tag,
        "--",
        *RULE_DIRS,
    )
    tokens = raw.split("\0")
    changes = []
    i = 0
    while i < len(tokens):
        field = tokens[i]
        if not field:
            i += 1
            continue
        status = field[0]
        score = int(field[1:]) if field[1:].isdigit() else 0
        if status in ("R", "C"):
            old_path, new_path = tokens[i + 1], tokens[i + 2]
            i += 3
        else:
            old_path = new_path = tokens[i + 1]
            i += 2
        if is_rule_path(old_path) or is_rule_path(new_path):
            changes.append((status, old_path, new_path, score))
    return changes


def load_rules_at(tag: str, path: str) -> list:
    """Parse every YAML document of a rule file at a given tag.

    Returns the list of documents that carry a top-level `id` (a single file
    may hold several, e.g. correlation rules). Missing files yield an empty
    list, which lets callers treat deletions uniformly.
    """
    try:
        blob = git("show", "{}:{}".format(tag, path))
    except subprocess.CalledProcessError:
        return []

    rules = []
    try:
        for doc in yaml.safe_load_all(blob):
            if isinstance(doc, dict) and "id" in doc:
                rules.append(doc)
    except yaml.YAMLError as error:
        print("[E] Could not parse {} at {}: {}".format(path, tag, error))
    return rules


def github_handle(name: str, email: str) -> str:
    """Resolve a git identity to a GitHub-style handle.

    Prefers the handle embedded in a GitHub noreply email; otherwise falls
    back to the commit author name (which, for web-UI contributors, already
    is the handle).
    """
    match = NOREPLY_RE.search(email or "")
    return match.group(1) if match else (name or "").strip()


def rule_summary(rule: dict) -> dict:
    return {
        "title": rule.get("title", ""),
        "status": rule.get("status", ""),
    }


def build_commit_index(from_tag: str, to_tag: str) -> tuple:
    """Derive, in a single `git log` pass, per rule path:

    - its merge date (date of the most recent commit touching it), and
    - the list of GitHub author handles that touched it (commit author plus
      any Co-authored-by trailers), bots excluded.

    The format uses control characters as field/record separators so that
    multi-line commit bodies parse unambiguously alongside the file list
    emitted by --name-only.
    """
    record_sep, field_sep = "\x1e", "\x1f"
    raw = git(
        "log",
        "--format={rs}%cs{fs}%an{fs}%ae{fs}%b{fs}".format(rs=record_sep, fs=field_sep),
        "--name-only",
        "-M",
        "{}..{}".format(from_tag, to_tag),
        "--",
        *RULE_DIRS,
    )

    merge_dates = {}
    authors = {}  # path -> ordered unique list of handles
    for record in raw.split(record_sep):
        if not record.strip():
            continue
        fields = record.split(field_sep)
        date, name, email, body = fields[0], fields[1], fields[2], fields[3]
        file_part = fields[4] if len(fields) > 4 else ""

        handles = [github_handle(name, email)]
        handles += [github_handle(n, e) for n, e in COAUTHOR_RE.findall(body)]
        handles = [h for h in handles if h and h.lower() not in BOT_AUTHORS]

        for path in file_part.splitlines():
            if not is_rule_path(path):
                continue
            merge_dates.setdefault(path, date.strip())
            seen = authors.setdefault(path, [])
            for handle in handles:
                if handle not in seen:
                    seen.append(handle)
    return merge_dates, authors


def build_changelog(from_tag: str, to_tag: str) -> dict:
    changes = parse_diff(from_tag, to_tag)
    merge_dates, authors_by_path = build_commit_index(from_tag, to_tag)

    prev_index = {}  # uuid -> summary at from_tag
    curr_index = {}  # uuid -> summary at to_tag
    content_changed = {}  # uuid -> bool (did the rule body actually change)
    paths = {}  # uuid -> representative path (for merge_date lookup)

    for status, old_path, new_path, score in changes:
        # Old side: rule existed before this release (modified/deleted/renamed).
        if status in ("M", "D", "R", "C"):
            for rule in load_rules_at(from_tag, old_path):
                prev_index[rule["id"]] = rule_summary(rule)
        # New side: rule exists after this release (added/modified/renamed).
        if status in ("M", "A", "R", "C"):
            changed = not (status in ("R", "C") and score == 100)
            for rule in load_rules_at(to_tag, new_path):
                uuid = rule["id"]
                curr_index[uuid] = rule_summary(rule)
                content_changed[uuid] = content_changed.get(uuid, False) or changed
                paths[uuid] = new_path
        else:
            for rule in load_rules_at(from_tag, old_path):
                paths.setdefault(rule["id"], old_path)

    changelog = {}
    for uuid in set(prev_index) | set(curr_index):
        prev = prev_index.get(uuid)
        curr = curr_index.get(uuid)

        if curr and not prev:
            change_type = "new"
        elif prev and not curr:
            change_type = "removed"
        elif (
            curr["status"] in END_OF_LIFE_STATUS
            and prev["status"] not in END_OF_LIFE_STATUS
        ):
            # Transitioned out of the active set this release. Report it as the
            # specific end-of-life status ("deprecated" or "unsupported").
            change_type = curr["status"]
        elif content_changed.get(uuid):
            change_type = "update"
        else:
            # Pure rename/move with identical content: the rule itself did not
            # change, so it does not belong in the changelog.
            continue

        source = curr or prev
        path = paths.get(uuid)
        changelog[uuid] = {
            "title": source["title"],
            "change_type": change_type,
            "change_reason": "",
            "authors": authors_by_path.get(path, []),
            "merge_date": merge_dates.get(path, ""),
        }

    # Sort by change type then title for a stable, reviewable output.
    ordered = dict(
        sorted(
            changelog.items(),
            key=lambda item: (
                CHANGE_TYPE_ORDER.index(item[1]["change_type"]),
                item[1]["title"].lower(),
            ),
        )
    )
    return ordered


def main(arguments: list) -> int:
    args = init_arguments(arguments)
    print("[I] Building changelog, this will take some time...")
    changelog = build_changelog(args.from_tag, args.to_tag)

    with open(args.outfile, "w", encoding="utf-8") as handle:
        json.dump(changelog, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    counts = {}
    for entry in changelog.values():
        counts[entry["change_type"]] = counts.get(entry["change_type"], 0) + 1
    summary = ", ".join("{} {}".format(counts.get(t, 0), t) for t in CHANGE_TYPE_ORDER)
    print("[I] {} rule changes ({})".format(len(changelog), summary))
    print("[I] Written changelog to '{}'".format(args.outfile))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
