"""Run evtx-sigma-checker against baselines and validate against known false positives.
"""

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml


def run_checker(
    checker: str,
    log_source: str,
    evtx_paths: list[str],
    rule_paths: list[str],
    findings_path: str,
) -> None:
    cmd = [checker, "--log-source", log_source]
    for p in evtx_paths:
        cmd += ["--evtx-path", p]
    for p in rule_paths:
        cmd += ["--rule-path", p]
    with open(findings_path, "w") as f:
        result = subprocess.run(cmd, stdout=f)
    if result.returncode != 0:
        raise RuntimeError(f"evtx-sigma-checker exited with code {result.returncode}")


def build_rule_index(rule_dirs: list[str], deprecated_dirs: list[str]) -> tuple[dict, set]:
    rules: dict[str, tuple[str, str]] = {}
    deprecated: set[str] = set()

    for d in rule_dirs:
        for path in Path(d).rglob("*.yml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "id" in data:
                    rules[data["id"]] = (str(path), data.get("title", ""))
            except Exception:
                pass

    for d in deprecated_dirs:
        for path in Path(d).rglob("*.yml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "id" in data:
                    deprecated.add(data["id"])
            except Exception:
                pass

    return rules, deprecated


def validate_known_fps(
    known_fps_path: str,
    rule_index: dict,
    deprecated: set,
) -> tuple[list[tuple[str, str]], list[str]]:
    valid_fps: list[tuple[str, str]] = []
    errors: list[str] = []

    with open(known_fps_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter=";")
        next(reader)
        for row in reader:
            if not row:
                continue
            fp_id = row[0].strip()
            fp_name = row[1].strip() if len(row) > 1 else ""
            fp_string = row[2].strip() if len(row) > 2 else ""

            if fp_id in rule_index:
                _, title = rule_index[fp_id]
                if title != fp_name:
                    errors.append(
                        f"Title mismatch for {fp_id}: "
                        f"CSV has '{fp_name}', rule has '{title}' - update known-FPs.csv"
                    )
                else:
                    valid_fps.append((fp_id, fp_string))
            elif fp_id in deprecated:
                errors.append(f"Deprecated rule in known-FPs.csv: {fp_id} ({fp_name}) - remove it")
            else:
                errors.append(f"Unknown rule ID in known-FPs.csv: {fp_id} ({fp_name})")

    return valid_fps, errors


def filter_findings(findings_path: str, valid_fps: list[tuple[str, str]]) -> list[str]:
    with open(findings_path, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    lines = [l for l in lines if '"RuleLevel":"low"' not in l]

    for fp_id, fp_string in valid_fps:
        id_pat = re.compile(rf'"RuleId":"{re.escape(fp_id)}"', re.IGNORECASE)
        fp_pat = re.compile(fp_string, re.IGNORECASE) if fp_string else None
        lines = [
            l for l in lines
            if not (id_pat.search(l) and (fp_pat is None or fp_pat.search(l)))
        ]

    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", default="findings.json", help="Path to findings JSON file")
    parser.add_argument("--known-fps", required=True, help="Path to known-FPs.csv")
    parser.add_argument(
        "--rule-paths",
        nargs="+",
        default=["rules/windows/", "rules-emerging-threats/", "rules-threat-hunting/"],
    )
    parser.add_argument("--deprecated-paths", nargs="+", default=["deprecated/"])
    parser.add_argument("--evtx-checker", help="Path to evtx-sigma-checker binary")
    parser.add_argument("--log-source", help="Path to log source config (e.g. tests/thor.yml)")
    parser.add_argument("--evtx-path", nargs="+", dest="evtx_paths", help="EVTX directories to scan")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not Path(args.findings).exists():
        if not args.evtx_checker:
            print(f"ERROR: {args.findings} not found and --evtx-checker not provided")
            return 1
        print("Running evtx-sigma-checker...")
        run_checker(args.evtx_checker, args.log_source, args.evtx_paths, args.rule_paths, args.findings)
        print("Done.\n")
    else:
        print(f"Using cached findings from {args.findings}\n")

    print("Building rule index...")
    rule_index, deprecated = build_rule_index(args.rule_paths, args.deprecated_paths)
    print(f"Indexed {len(rule_index)} rules, {len(deprecated)} deprecated\n")

    valid_fps, errors = validate_known_fps(args.known_fps, rule_index, deprecated)

    if errors:
        print("ERROR: known-FPs.csv validation failed:")
        for e in errors:
            print(f"  {e}")
        return 4

    remaining = filter_findings(args.findings, valid_fps)

    if not remaining:
        print("No unexpected matches found.")
        return 0

    print(f"Found {len(remaining)} unexpected match(es):\n")
    for line in remaining:
        print(line)

    counts: dict[tuple, int] = {}
    for line in remaining:
        try:
            obj = json.loads(line)
            key = (obj.get("RuleId"), obj.get("RuleTitle"), obj.get("RuleLevel"))
            counts[key] = counts.get(key, 0) + 1
        except json.JSONDecodeError:
            pass

    print("\nMatch overview:")
    for (rid, title, level), count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {count}x [{level}] {title} ({rid})")

    print("\nYou either need to tune your rule(s) for false positives or add a false positive filter to .github/workflows/known-FPs.csv")
    return 3


if __name__ == "__main__":
    sys.exit(main())
