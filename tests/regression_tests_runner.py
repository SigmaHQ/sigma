"""Run regression tests for Sigma rules.

Unlike the old runner, rules do NOT declare a `regression_tests_path`. Instead
this script walks the `regression_data/` tree for `info.yml` files and, for
each one, looks up the Sigma rule(s) by the `id`s listed under `rules`, then
executes the `test_cases`.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional

import yaml

try:
    from yaml import CSafeLoader as _YAMLLoader
except ImportError:
    from yaml import SafeLoader as _YAMLLoader  # type: ignore[assignment]


def get_absolute_path(base_path: str, relative_path: str) -> str:
    """Convert a relative path to an absolute path based on a base path."""
    if os.path.isabs(relative_path):
        return relative_path

    relative_path = relative_path.replace("/", os.sep).replace("\\", os.sep)
    workspace_root = base_path
    while not os.path.exists(os.path.join(workspace_root, relative_path)):
        parent = os.path.dirname(workspace_root)
        if parent == workspace_root:  # Reached filesystem root
            break
        workspace_root = parent
    return os.path.join(workspace_root, relative_path)


def _read_rule(file_path: str) -> tuple[Optional[str], str, str]:
    """Return (rule_id, status, file_path) for a Sigma rule file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rule_data = yaml.load(f, Loader=_YAMLLoader)
        if isinstance(rule_data, dict):
            return rule_data.get("id"), str(rule_data.get("status", "")).lower(), file_path
    except yaml.YAMLError as e:
        print(f"Warning: Could not parse {file_path}: {e}")
    return None, "", file_path


def build_rule_index(rules_paths: List[str]) -> tuple[Dict[str, str], Dict[str, str]]:
    """Scan rule directories.

    Returns:
        tuple: (index, status_by_id) where index maps rule id -> file path and
        status_by_id maps rule id -> status.
    """
    all_files = []
    for rules_path in rules_paths:
        if not os.path.exists(rules_path):
            print(f"Warning: Rules path {rules_path} does not exist")
            continue
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith(".yml"):
                    all_files.append(os.path.join(root, file))

    index: Dict[str, str] = {}
    status_by_id: Dict[str, str] = {}
    for file_path in all_files:
        rule_id, status, path = _read_rule(file_path)
        if not rule_id:
            continue
        if rule_id in index:
            print(
                f"Warning: Duplicate rule id '{rule_id}' in {path} "
                f"(already seen at {index[rule_id]})"
            )
            continue
        index[rule_id] = path
        status_by_id[rule_id] = status
    return index, status_by_id


def load_info_yaml(
    info_path: str, rule_index: Dict[str, str]
) -> tuple[List[Dict], List[Dict], List[Dict]]:
    """Parse a regression-test info.yml file.

    Returns:
        tuple: (results, missing_files, missing_rules)
    """
    results: List[Dict] = []
    missing_files: List[Dict] = []
    missing_rules: List[Dict] = []

    try:
        with open(info_path, "r", encoding="utf-8") as f:
            info_data = yaml.load(f, Loader=_YAMLLoader)
    except yaml.YAMLError as e:
        print(f"Warning: Could not parse info file {info_path}: {e}")
        return results, missing_files, missing_rules

    if not info_data or "test_cases" not in info_data:
        print(f"Warning: No test_cases found in {info_path}")
        return results, missing_files, missing_rules

    base_dir = os.path.dirname(info_path)
    rules = info_data.get("rules", [])
    test_cases = info_data.get("test_cases", [])
    # Root-level pipelines as a fallback; test_cases[*].pipelines takes precedence.
    root_pipelines = info_data.get("pipelines", [])

    # Parse test cases once (shared by every rule listed in this info.yml).
    test_data = []
    for test in test_cases:
        if not isinstance(test, dict):
            continue

        test_path = get_absolute_path(base_dir, test.get("path", ""))
        pipelines = [
            get_absolute_path(base_dir, p)
            for p in test.get("pipelines", root_pipelines)
        ]
        filters = [get_absolute_path(base_dir, f) for f in test.get("filters", [])]

        test_data.append(
            {
                "type": test.get("type", "unknown"),
                "path": test_path,
                "name": test.get("name", "Unnamed Test"),
                "provider": test.get("provider", ""),
                "match_count": test.get("match_count"),
                "pipelines": pipelines,
                "filters": filters,
            }
        )

    if not test_data:
        return results, missing_files, missing_rules

    for rule_entry in rules:
        if not isinstance(rule_entry, dict):
            continue
        rule_id = rule_entry.get("id")
        if not rule_id:
            continue

        rule_path = rule_index.get(rule_id)
        if not rule_path:
            missing_rules.append(
                {
                    "rule_id": rule_id,
                    "info_path": info_path,
                }
            )
            continue

        # Check referenced test data files exist (once per resolved rule).
        for test in test_data:
            if not os.path.exists(test["path"]):
                missing_files.append(
                    {
                        "rule_path": rule_path,
                        "rule_id": rule_id,
                        "missing_file": test["path"],
                        "file_type": "test_file",
                        "test_name": test["name"],
                        "test_type": test["type"],
                    }
                )

        results.append(
            {
                "path": rule_path,
                "id": rule_id,
                "info_path": info_path,
                "tests": test_data,
            }
        )

    return results, missing_files, missing_rules


def find_info_files(regression_data_paths: List[str]) -> List[str]:
    """Find all info.yml files under the regression_data tree(s)."""
    info_files = []
    for base in regression_data_paths:
        if not os.path.exists(base):
            print(f"Warning: regression_data path {base} does not exist")
            continue
        for root, _, files in os.walk(base):
            for file in files:
                if file == "info.yml":
                    info_files.append(os.path.join(root, file))
    return info_files


def find_rules_with_tests(
    rules_paths: List[str],
    regression_data_paths: List[str],
) -> tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
    """Find all rules that have regression tests defined under regression_data_paths.

    Returns:
        tuple: (rules_with_tests, missing_files, missing_rules,
                missing_regression_tests)
    """
    rule_index, status_by_id = build_rule_index(rules_paths)

    results: List[Dict] = []
    missing_files: List[Dict] = []
    missing_rules: List[Dict] = []

    for info_path in find_info_files(regression_data_paths):
        r, mf, mr = load_info_yaml(info_path, rule_index)
        results.extend(r)
        missing_files.extend(mf)
        missing_rules.extend(mr)

    # test/stable rules must have regression tests defined
    tested_ids = {r["id"] for r in results}
    missing_regression_tests = [
        {"rule_id": rid, "rule_path": rule_index[rid], "status": status}
        for rid, status in status_by_id.items()
        if status in ("test", "stable") and rid not in tested_ids
    ]

    return results, missing_files, missing_rules, missing_regression_tests


def _link(src: str, dst: str) -> None:
    """Hardlink src to dst, falling back to copy if cross-filesystem."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def run_evtx_checker(
    rule_path: str,
    rule_id: str,
    test_data: Dict,
    evtx_checker_path: str,
    thor_config: str,
) -> tuple[bool, str]:
    """Run evtx-sigma-checker for a single rule against a single EVTX file."""
    evtx_path = test_data["path"]

    with tempfile.TemporaryDirectory() as tmpdir:
        rules_dir = os.path.join(tmpdir, "rules")
        evtx_dir = os.path.join(tmpdir, "evtx")
        os.makedirs(rules_dir)
        os.makedirs(evtx_dir)

        rule_dst = os.path.join(rules_dir, f"{rule_id}.yml")
        _link(os.path.abspath(rule_path), rule_dst)
        _link(os.path.abspath(evtx_path), os.path.join(evtx_dir, os.path.basename(evtx_path)))

        cmd = [
            evtx_checker_path,
            "--log-source", thor_config,
            "--evtx-path", evtx_dir,
            "--rule-level", "informational",
            "--rule-path", rules_dir,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            print(f"  Timeout: evtx-sigma-checker timed out for {rule_id}")
            return False, ""

        if result.returncode != 0:
            stderr = result.stderr.replace(rule_dst, rule_path)
            print(f"  Error: evtx-sigma-checker exited with code {result.returncode}: {stderr.strip()}")
            return False, ""

        match_lines = []
        for line in result.stdout.strip().splitlines():
            try:
                if json.loads(line).get("RuleId") == rule_id:
                    match_lines.append(line)
            except json.JSONDecodeError:
                print(f"  Warning: Skipping non-JSON line: {line}")

        return _evaluate_matches(rule_id, "evtx", test_data, match_lines)


def _evaluate_matches(
    rule_id: str, test_type: str, test_data: Dict, match_lines: List[str]
) -> tuple[bool, str]:
    """Compare the number of matches against the expected match_count."""
    match_count = len(match_lines)
    all_output = "\n    ".join(match_lines)
    test_name = test_data.get("name", "Unnamed Test")
    expected_count = test_data.get("match_count")

    if expected_count is not None:
        if match_count < expected_count:
            print(f"  Error: {rule_id} - {test_name} (type: {test_type}): Match count too low: expected {expected_count}, got {match_count}")
            return False, all_output
        if match_count > expected_count:
            print(f"  Error: {rule_id} - {test_name} (type: {test_type}): Got {match_count} matches but only {expected_count} expected - consider updating match_count in info.yml")
            return False, all_output
        return True, all_output

    return match_count > 0, all_output


def compile_rule_to_expr(
    rule_path: str, pipelines: List[str], filters: List[str]
) -> str:
    """Compile a Sigma rule to a golang_expr query via the sigma CLI."""
    cmd = ["sigma", "convert", "-t", "golang_expr"]
    for pipeline in pipelines:
        cmd += ["-p", pipeline]
    if len(pipelines) == 0:
        cmd += ["--without-pipeline"]
    for filter in filters:
        cmd += ["--filter", filter]
    cmd.append(rule_path)

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300, check=True
    )

    return result.stdout.strip()


def run_json_checker(
    test_type: str,
    rule_path: str,
    rule_id: str,
    test_data: Dict,
    json_checker_path: str,
) -> tuple[bool, str]:
    """Compile the rule to an expr query and run json_checker against the events."""
    try:
        expr_query = compile_rule_to_expr(
            rule_path, test_data.get("pipelines", []), test_data.get("filters", [])
        )
    except subprocess.CalledProcessError as e:
        print(f"  Error compiling rule {rule_id} with sigma: {e.stderr or e}")
        return False, ""
    except subprocess.TimeoutExpired:
        print(f"  Timeout compiling rule {rule_id} with sigma")
        return False, ""

    if not expr_query:
        print(f"  Error: sigma produced an empty expr query for {rule_id}")
        return False, ""

    cmd = [json_checker_path, "--event", test_data["path"], "--expr", expr_query, "--test-type", test_type]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=True
        )
    except subprocess.TimeoutExpired:
        print("  Timeout: json_checker timed out")
        return False, ""
    except subprocess.CalledProcessError as e:
        print(f"  Error running json_checker: {e.stderr or e}")
        return False, ""

    match_lines = [ln for ln in result.stdout.splitlines() if ln.endswith("MATCH")]
    return _evaluate_matches(rule_id, test_type, test_data, match_lines)


def run_test(
    args: argparse.Namespace,
    rule_path: str,
    rule_id: str,
    test_data: Dict,
) -> tuple[bool, str]:
    """Run a single test based on its type."""
    test_type = test_data.get("type", "unknown")

    if test_type == "evtx":
        return run_evtx_checker(rule_path, rule_id, test_data, args.evtx_checker, args.thor_config)
    if test_type in {"json", "ndjson", "jsonl"}:
        if not args.json_checker:
            print("  Error: --json-checker is required for 'ndjson/json/jsonl' tests")
            return False, ""
        return run_json_checker(test_type, rule_path, rule_id, test_data, args.json_checker)
    print(f"  Warning: Unknown test type '{test_type}', skipping")
    return False, ""


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run regression tests for Sigma rules defined under regression_data/"
    )

    parser.add_argument(
        "--rules-paths",
        required=True,
        action="extend",
        nargs="+",
        help="Paths to rule directories (used to look up rules by id)",
    )

    parser.add_argument(
        "--regression-data",
        action="extend",
        nargs="+",
        default=None,
        help="Paths to regression_data directories containing info.yml files (default: regression_data)",
    )

    parser.add_argument(
        "--evtx-checker",
        help="Path to evtx-sigma-checker binary (required unless using --validate-only)",
    )

    parser.add_argument(
        "--thor-config",
        help="Path to thor.yml configuration file (required unless using --validate-only)",
    )

    parser.add_argument(
        "--json-checker",
        help="Path to json_checker binary (required for 'ndjson/json/jsonl' tests)",
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate that rules and test files exist, without running tests",
    )

    parser.add_argument(
        "--ignore-validation",
        action="store_true",
        help="Ignore rule status validation requirements",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output, showing successful test results as well",
    )

    args = parser.parse_args()
    if not args.regression_data:
        args.regression_data = ["regression_data"]
    return args


def init_checks(args: argparse.Namespace) -> None:
    """Initialization that checks for functional environment."""
    if args.validate_only:
        print("Starting Regression Test Validation...")
    else:
        print("Starting Regression Tests...")

        if not args.evtx_checker or not args.thor_config:
            print(
                "Error: --evtx-checker and --thor-config are required unless using --validate-only"
            )
            sys.exit(1)

        if not os.path.exists(args.evtx_checker):
            print(f"Error: evtx-sigma-checker not found at {args.evtx_checker}")
            sys.exit(1)

        if not os.path.exists(args.thor_config):
            print(f"Error: Thor config not found at {args.thor_config}")
            sys.exit(1)

        if args.json_checker and not os.path.exists(args.json_checker):
            print(f"Error: json_checker not found at {args.json_checker}")
            sys.exit(1)

    print(f"Rules paths: {args.rules_paths}")
    print(f"Regression data: {args.regression_data}")
    if not args.validate_only:
        print(f"EVTX checker: {args.evtx_checker}")
        print(f"Thor config: {args.thor_config}")
    print()


def run_tests(
    args: argparse.Namespace, rules_with_tests
) -> tuple[int, int, List[Dict]]:
    """Run every test, one subprocess call per test."""
    failures = []
    passed_tests = 0
    total_tests = 0

    for rule_info in rules_with_tests:
        rule_id = rule_info["id"]
        rule_path = rule_info["path"]
        for i, test_data in enumerate(rule_info["tests"]):
            total_tests += 1
            test_name = test_data.get("name", f"Test {i + 1}")
            test_type = test_data.get("type", "unknown")
            test_path = test_data.get("path", "unknown")

            if args.verbose:
                print(f"\nTesting rule: {rule_id} - {test_name} (type: {test_type}): {test_path}")

            success, output = run_test(args, rule_path, rule_id, test_data)

            if args.verbose:
                if success:
                    print(f"    ✓ PASS - Match found for Rule ID: {rule_id}")
                    if output:
                        print(f"    Output: {output}")
                else:
                    print(f"    ✗ FAIL: {rule_id} - {test_name} (type: {test_type}): {test_path}")
                    print(f"    Output: {output if output else '(no matches)'}")

            if success:
                passed_tests += 1
            else:
                failures.append({
                    "rule_id": rule_id,
                    "rule_path": rule_path,
                    "test_name": test_name,
                    "test_type": test_type,
                    "test_path": test_path,
                    "test_number": i + 1,
                })

    return total_tests, passed_tests, failures


def check_missing_rules(missing_rules: List[Dict]) -> None:
    """Print rule ids referenced in info.yml files that were not found."""
    if not missing_rules:
        return

    print(f"\nERROR: Found {len(missing_rules)} rule id(s) referenced in "
          "info.yml but not found in the rule directories:")
    print("=" * 60)
    for missing in missing_rules:
        print(f"Rule ID: {missing['rule_id']}")
        print(f"  Referenced in: {missing['info_path']}")
        print()
    print("=" * 60)
    print("Ensure every id under 'rules' in info.yml matches an existing Sigma rule.")
    sys.exit(1)


def check_missing_regression_tests(
    missing_regression_tests: List[Dict], ignore_validation: bool
) -> None:
    """Enforce that test/stable rules have regression tests defined."""
    if not missing_regression_tests:
        return

    count = len(missing_regression_tests)
    if ignore_validation:
        print(
            f"\nWARNING: Found {count} test/stable rule(s) without regression tests "
            "(validation ignored)"
        )
        return

    print("\n" + "=" * 60)
    print("RULES MISSING REGRESSION TESTS:")
    print("=" * 60)
    for missing in missing_regression_tests:
        print(f"Rule: {missing['rule_id']} (status: {missing['status']})")
        print(f"  File: {missing['rule_path']}")
        print()
    print("=" * 60)
    print("Rules with status 'test' or 'stable' must have regression tests defined "
          "under regression_data (an info.yml referencing the rule id).")
    print(f"\nERROR: Found {count} test/stable rule(s) without regression tests.")
    sys.exit(1)


def check_missing_test_files(missing_files: List[Dict]) -> None:
    """Check for missing test data files and print errors if any are found."""
    if not missing_files:
        return

    print(f"\nERROR: Found {len(missing_files)} missing test data file(s):")
    print("=" * 60)
    print("-" * 50)
    for missing in missing_files:
        print(f"Rule: {missing['rule_id']}")
        print(f"  File: {missing['rule_path']}")
        print(f"  Test: {missing['test_name']} (type: {missing['test_type']})")
        print(f"  Missing: {missing['missing_file']}")
        print()
    print("=" * 60)
    print("Please ensure all referenced files exist before running tests.")
    sys.exit(1)


def print_summary(total_tests: int, passed_tests: int, failures: List[Dict]) -> None:
    """Print a summary of the test results."""
    print("=" * 60)
    print("REGRESSION TEST SUMMARY")
    print("=" * 60)
    print(f"Total tests run: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {len(failures)}")

    if total_tests > 0:
        success_rate = (passed_tests / total_tests) * 100
        print(f"Success rate: {success_rate:.1f}%")

    if failures:
        print(f"\nFAILED TESTS ({len(failures)}):")
        print("-" * 40)
        for failure in failures:
            print(f"Rule: {failure['rule_id']}")
            print(f"  File: {failure['rule_path']}")
            print(f"  Test: {failure['test_name']} (type: {failure['test_type']})")
            print(f"  Path: {failure['test_path']}")
            print()

    print("=" * 60)


def main():
    """Main function to run regression tests for Sigma rules."""
    args = parse_arguments()
    init_checks(args)

    print("Scanning regression_data for info.yml files...")
    rules_with_tests, missing_files, missing_rules, missing_regression_tests = (
        find_rules_with_tests(args.rules_paths, args.regression_data)
    )
    print(f"Found {len(rules_with_tests)} rule(s) with regression tests configured.\n")
    for info_path in sorted({r["info_path"] for r in rules_with_tests}):
        print(f"  {info_path}")
    print()

    check_missing_rules(missing_rules)
    check_missing_regression_tests(missing_regression_tests, args.ignore_validation)
    check_missing_test_files(missing_files)

    if args.validate_only:
        print("✅ All rules passed validation!")
        print(f"Found {len(rules_with_tests)} rules with regression tests configured.")
        sys.exit(0)

    print()
    if not rules_with_tests:
        print("No rules with test data found")
        sys.exit(1)

    print("Running tests...\n")
    total_tests, passed_tests, failures = run_tests(args, rules_with_tests)

    print_summary(total_tests, passed_tests, failures)

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
