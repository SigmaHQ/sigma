"""Run regression tests for Sigma rules based on their regression_tests_path attribute."""

import argparse
import concurrent.futures
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

    # Normalize path separators
    relative_path = relative_path.replace("/", os.sep).replace("\\", os.sep)
    workspace_root = base_path
    while not os.path.exists(os.path.join(workspace_root, relative_path)):
        parent = os.path.dirname(workspace_root)
        if parent == workspace_root:  # Reached filesystem root
            break
        workspace_root = parent
    return os.path.join(workspace_root, relative_path)


def load_info_yaml(
    regression_tests_path: str, rule_id: str, file_path: str
) -> tuple[List[Dict], List[Dict]]:
    """Load and parse the regression test info YAML file."""
    results = []
    missing_files = []

    if not os.path.exists(regression_tests_path):
        missing_files.append(
            {
                "rule_path": file_path,
                "rule_id": rule_id,
                "missing_file": regression_tests_path,
                "file_type": "regression_tests_path",
            }
        )
        return results, missing_files

    try:
        with open(regression_tests_path, "r", encoding="utf-8") as f:
            info_data = yaml.load(f, Loader=_YAMLLoader)

        if not info_data or "regression_tests_info" not in info_data:
            print(f"Warning: No regression_tests_info found in {regression_tests_path}")
            return results, missing_files

        # Extract test data from regression_tests_info
        test_data = []
        regression_tests = info_data.get("regression_tests_info", [])
        rule_metadata = info_data.get("rule_metadata", [])

        for test in regression_tests:
            if not isinstance(test, dict):
                continue

            test_path = get_absolute_path(
                os.path.dirname(file_path), test.get("path", "")
            )

            # Check if test file exists
            if not os.path.exists(test_path):
                missing_files.append(
                    {
                        "rule_path": file_path,
                        "rule_id": rule_id,
                        "missing_file": test_path,
                        "file_type": "test_file",
                        "test_name": test.get("name", "Unnamed Test"),
                        "test_type": test.get("type", "unknown"),
                    }
                )

            base_dir = os.path.dirname(regression_tests_path)
            pipelines = [
                get_absolute_path(base_dir, p) for p in test.get("pipelines", [])
            ]
            filters = [
                get_absolute_path(base_dir, f) for f in test.get("filters", [])
            ]

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
        info_metadata_rule_id = None
        for metadata_entry in rule_metadata:
            if not isinstance(metadata_entry, dict):
                continue
            info_metadata_rule_id = metadata_entry.get("id", "")

        if test_data:
            results.append(
                {
                    "path": file_path,
                    "id": rule_id,
                    "tests": test_data,
                    "info_metadata_rule_id": info_metadata_rule_id,
                }
            )

    except yaml.YAMLError as e:
        print(f"Warning: Could not parse info file {regression_tests_path}: {e}")

    return results, missing_files


def find_rule_missing_test(rule_data: Dict, file_path: str) -> tuple[bool, List[Dict]]:
    """Find missing test files for a single rule based on its data.

    Returns:
        skip: True if the rule should be skipped, False otherwise
        missing_regression_tests_path: List of dicts with missing regression_tests_path info

    """
    missing_regression_tests_path = []
    rule_id = rule_data.get("id", "unknown")
    rule_status = rule_data.get("status", "").lower()

    # Check if rule status requires regression tests
    requires_regression_tests = rule_status in ["test", "stable"]

    # Check if rule has regression_tests_path
    has_regression_tests_path = "regression_tests_path" in rule_data

    # If rule requires regression tests but doesn't have regression_tests_path
    if requires_regression_tests and not has_regression_tests_path:
        missing_regression_tests_path.append(
            {
                "rule_path": file_path,
                "rule_id": rule_id,
                "status": rule_status,
            }
        )
        return True, missing_regression_tests_path

    # Skip rules that don't require regression tests
    # and don't have regression_tests_path
    if not requires_regression_tests and not has_regression_tests_path:
        return True, missing_regression_tests_path
    return False, missing_regression_tests_path


def find_rule_tests(rule_data: Dict, file_path: str) -> tuple[List[Dict], List[Dict]]:
    """Find regression tests and missing files for a single rule based on its data."""
    results = []
    missing_files = []
    rule_id = rule_data.get("id", "unknown")

    if rule_data and "regression_tests_path" in rule_data:
        regression_tests_path = get_absolute_path(
            os.path.dirname(file_path),
            rule_data.get("regression_tests_path", ""),
        )

        # Load the info.yml file
        yml_result, yml_missing_files = load_info_yaml(
            regression_tests_path, rule_id, file_path
        )
        results.extend(yml_result)
        missing_files.extend(yml_missing_files)
    return results, missing_files


def _process_rule_file(
    file_path: str,
) -> tuple[List[Dict], List[Dict], List[Dict]]:
    """Load and process a single rule file.

    Returns:
        tuple: (results, missing_files, missing_regression_tests_path)
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rule_data = yaml.load(f, Loader=_YAMLLoader)
        if not rule_data:
            return [], [], []
        skip, missing_test = find_rule_missing_test(rule_data, file_path)
        if skip:
            return [], [], missing_test
        result, missing_file = find_rule_tests(rule_data, file_path)
        return result, missing_file, missing_test
    except yaml.YAMLError as e:
        print(f"Warning: Could not parse {file_path}: {e}")
        return [], [], []


def find_rules_with_tests(
    rules_paths: List[str],
    workers: Optional[int] = None,
) -> tuple[List[Dict], List[Dict], List[Dict]]:
    """Find all rules that have a 'regression_tests_path' attribute pointing to test info files.

    Returns:
        tuple: (rules_with_tests, missing_files, missing_regression_tests_path)
    """
    results = []
    missing_files = []
    missing_regression_tests_path = []

    all_files = []
    for rules_path in rules_paths:
        if not os.path.exists(rules_path):
            print(f"Warning: Rules path {rules_path} does not exist")
            continue
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith(".yml"):
                    all_files.append(os.path.join(root, file))

    with concurrent.futures.ThreadPoolExecutor(max_workers=_default_workers(workers)) as executor:
        for r, mf, mrp in executor.map(_process_rule_file, all_files):
            results.extend(r)
            missing_files.extend(mf)
            missing_regression_tests_path.extend(mrp)

    return results, missing_files, missing_regression_tests_path


def _default_workers(n: Optional[int]) -> int:
    return n if n is not None else min(32, (os.cpu_count() or 1) * 4)


def _link(src: str, dst: str) -> None:
    """Hardlink src to dst, falling back to copy if cross-filesystem."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def run_evtx_batch(
    evtx_test_items: List[tuple],
    evtx_checker_path: str,
    thor_config: str,
) -> Dict[str, List[str]]:
    """Run evtx-sigma-checker once for all EVTX tests.

    Returns:
        Dict mapping rule_id -> list of matching JSON output lines
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_dir = os.path.join(tmpdir, "rules")
        evtx_dir = os.path.join(tmpdir, "evtx")
        os.makedirs(rules_dir)
        os.makedirs(evtx_dir)

        for rule_info, _, test_data in evtx_test_items:
            rule_path = rule_info["path"]
            evtx_path = test_data["path"]
            rule_id = rule_info["id"]

            # Use rule_id as filename to avoid collisions across directories
            rule_dst = os.path.join(rules_dir, f"{rule_id}.yml")
            if not os.path.exists(rule_dst):
                _link(os.path.abspath(rule_path), rule_dst)

            if os.path.exists(evtx_path):
                evtx_dst = os.path.join(evtx_dir, os.path.basename(evtx_path))
                if not os.path.exists(evtx_dst):
                    _link(os.path.abspath(evtx_path), evtx_dst)
                else:
                    print(
                        f"  Warning: EVTX filename collision for '{os.path.basename(evtx_path)}' "
                        f"(rule {rule_id}) - file already staged from another rule; "
                        "review info.yml to ensure unique EVTX filenames"
                    )

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
            print("  Timeout: batched evtx-sigma-checker timed out")
            return {}

        if result.returncode != 0:
            print(f"  Warning: evtx-sigma-checker exited with code {result.returncode}: {result.stderr}")

        matches: Dict[str, List[str]] = {}
        for line in result.stdout.strip().splitlines():
            try:
                json_obj = json.loads(line)
                rid = json_obj.get("RuleId")
                evtx_stem = os.path.splitext(os.path.basename(json_obj.get("File", "")))[0]
                if rid and evtx_stem == rid:
                    matches.setdefault(rid, []).append(line)
            except json.JSONDecodeError:
                print(f"  Warning: Skipping non-JSON line: {line}")

        return matches


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
    match_count = len(match_lines)
    all_output = "\n    ".join(match_lines)

    expected_count = test_data.get("match_count")
    if expected_count is not None:
        if match_count < expected_count:
            print(
                f"  Error: {rule_id}: Match count too low: expected {expected_count}, got {match_count}"
            )
            return False, all_output
        if match_count > expected_count:
            print(
                f"  Warning: {rule_id}: Got {match_count} matches but only {expected_count} expected - consider updating match_count in info.yml"
            )
        return True, all_output

    return match_count > 0, all_output


def run_test(
    rule_path: str,
    rule_id: str,
    test_data: Dict,
    json_checker_path: str,
) -> tuple[bool, str]:
    """Run a test based on its type."""
    test_type = test_data.get("type", "unknown")

    if test_type in {"json", "ndjson", "jsonl"}:
        if not json_checker_path:
            print("  Error: --json-checker is required for 'ndjson/json/jsonl' tests")
            return False, ""
        return run_json_checker(test_type, rule_path, rule_id, test_data, json_checker_path)
    print(f"  Warning: Unknown test type '{test_type}', skipping")
    return False, ""


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run regression tests for Sigma rules with regression_tests_path"
    )

    parser.add_argument(
        "--rules-paths",
        required=True,
        action="extend",
        nargs="+",
        help="Comma-separated paths to rule directories",
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
        help="Only validate rule status requirements without running tests",
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

    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers for running tests (default: auto based on CPU count)",
    )

    args = parser.parse_args()
    if args.workers is not None and args.workers < 1:
        parser.error("--workers must be >= 1")
    return args


def init_checks(args: argparse.Namespace) -> None:
    """Initialization that checks for functional environment."""
    if args.validate_only:
        print("Starting Rule Status Validation...")
    else:
        print("Starting Regression Tests...")

        # Check required arguments for test execution
        if not args.evtx_checker or not args.thor_config:
            print(
                "Error: --evtx-checker and --thor-config are required unless using --validate-only"
            )
            sys.exit(1)

        # Check if evtx-sigma-checker exists
        if not os.path.exists(args.evtx_checker):
            print(f"Error: evtx-sigma-checker not found at {args.evtx_checker}")
            sys.exit(1)

        # Check if THOR config exists
        if not os.path.exists(args.thor_config):
            print(f"Error: Thor config not found at {args.thor_config}")
            sys.exit(1)

        # json_checker is optional; only needed for 'ndjson/json/jsonl' tests
        if args.json_checker and not os.path.exists(args.json_checker):
            print(f"Error: json_checker not found at {args.json_checker}")
            sys.exit(1)
        print(f"Rules paths: {args.rules_paths}")

    if not args.validate_only:
        print(f"EVTX checker: {args.evtx_checker}")
        print(f"Thor config: {args.thor_config}")
    print()


def run_tests(
    args: argparse.Namespace, rules_with_tests
) -> tuple[int, int, List[Dict]]:
    """Run tests for all rules: EVTX tests in one batch call, JSON tests in parallel."""
    failures = []
    passed_tests = 0

    all_test_items = [
        (rule_info, i, test_data)
        for rule_info in rules_with_tests
        for i, test_data in enumerate(rule_info["tests"])
    ]
    total_tests = len(all_test_items)

    evtx_items = [(ri, i, td) for ri, i, td in all_test_items if td.get("type") == "evtx"]
    other_items = [(ri, i, td) for ri, i, td in all_test_items if td.get("type") != "evtx"]

    # --- EVTX: single batched subprocess call ---
    if evtx_items:
        batch_matches = run_evtx_batch(evtx_items, args.evtx_checker, args.thor_config)

        for rule_info, i, test_data in evtx_items:
            rule_id = rule_info["id"]
            rule_path = rule_info["path"]
            test_name = test_data.get("name", f"Test {i + 1}")
            test_type = "evtx"
            test_path = test_data.get("path", "unknown")

            match_outputs = batch_matches.get(rule_id, [])
            match_count = len(match_outputs)
            all_output = "\n    ".join(match_outputs)
            expected_count = test_data.get("match_count")

            if expected_count is not None:
                if match_count < expected_count:
                    print(f"  Error: {rule_id}: Match count too low: expected {expected_count}, got {match_count}")
                    success = False
                else:
                    if match_count > expected_count:
                        print(f"  Warning: {rule_id}: Got {match_count} matches but only {expected_count} expected - consider updating match_count in info.yml")
                    success = True
            else:
                success = match_count > 0

            if args.verbose:
                if success:
                    print(f"    ✓ PASS - Match found for Rule ID: {rule_id}")
                    if all_output:
                        print(f"    Output: {all_output}")
                else:
                    print(f"    ✗ FAIL: {rule_id}")

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

    # --- JSON/NDJSON/JSONL: parallel workers ---
    if other_items:
        def run_single(item: tuple) -> tuple:
            rule_info, i, test_data = item
            rule_path = rule_info["path"]
            rule_id = rule_info["id"]
            test_name = test_data.get("name", f"Test {i + 1}")
            test_type = test_data.get("type", "unknown")
            test_path = test_data.get("path", "unknown")

            if args.verbose:
                print(f"\nTesting rule: {rule_id} - {test_name} (type: {test_type}): {test_path}")

            success, output = run_test(
                rule_path, rule_id, test_data, args.json_checker,
            )

            if args.verbose:
                if success:
                    print(f"    ✓ PASS - Match found for Rule ID: {rule_id}")
                    if output:
                        print(f"    Output: {output}")
                else:
                    print(f"    ✗ FAIL: {rule_id}")

            return success, rule_id, rule_path, test_name, test_type, test_path, i + 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=_default_workers(args.workers)) as executor:
            futures = [executor.submit(run_single, item) for item in other_items]
            for future in concurrent.futures.as_completed(futures):
                success, rule_id, rule_path, test_name, test_type, test_path, test_num = future.result()
                if success:
                    passed_tests += 1
                else:
                    failures.append({
                        "rule_id": rule_id,
                        "rule_path": rule_path,
                        "test_name": test_name,
                        "test_type": test_type,
                        "test_path": test_path,
                        "test_number": test_num,
                    })

    return total_tests, passed_tests, failures


def validate_missing_tests(
    args: argparse.Namespace,
    rules_with_tests: List[Dict],
    missing_regression_tests_path: List[Dict],
) -> None:
    """Print rules missing regression_tests_path and handle validation."""

    # Check for missing regression_tests_path in test/stable rules
    if missing_regression_tests_path and not args.ignore_validation:
        print()
        print("-" * 50)
        print("RULES MISSING REGRESSION_TESTS_PATH:")
        print("-" * 50)
        for missing in missing_regression_tests_path:
            print(f"Rule: {missing['rule_id']} (status: {missing['status']})")
            print(f"  File: {missing['rule_path']}")
            print()
        print("=" * 70)
        print(
            "Rules with status 'test' or 'stable' must have a 'regression_tests_path' field."
        )
        print("Please add regression tests for these rules or change their status.")
        print("=" * 70)
        print(
            f"\nERROR: Found {len(missing_regression_tests_path)} "
            "test/stable rule(s) without regression_tests_path."
        )

        sys.exit(1)
    elif missing_regression_tests_path and args.ignore_validation:
        print(
            f"\nWARNING: Found {len(missing_regression_tests_path)} "
            "test/stable rule(s) without regression_tests_path (validation ignored)"
        )
        print(
            "Consider adding regression tests for these rules "
            "or changing their status to 'experimental'."
        )

    # If validate-only mode, exit successfully after validation
    if args.validate_only:
        if args.ignore_validation and missing_regression_tests_path:
            print("✅ All rules passed validation (validation ignored)!")
        else:
            print("✅ All rules passed validation!")
        print(f"Found {len(rules_with_tests)} rules with regression tests configured.")
        sys.exit(0)


def check_missing_test_files(missing_files: List[Dict]) -> None:
    """Check for missing test files and print errors if any are found."""
    if not missing_files:
        return

    print(f"\nERROR: Found {len(missing_files)} missing file(s):")
    print("=" * 60)

    regression_test_files = [
        f for f in missing_files if f["file_type"] == "regression_tests_path"
    ]
    test_files = [f for f in missing_files if f["file_type"] == "test_file"]

    if regression_test_files:
        print(f"\nMISSING REGRESSION TEST INFO FILES ({len(regression_test_files)}):")
        print("-" * 50)
        for missing in regression_test_files:
            print(f"Rule: {missing['rule_id']}")
            print(f"  File: {missing['rule_path']}")
            print(f"  Missing: {missing['missing_file']}")
            print()

    if test_files:
        print(f"\nMISSING TEST DATA FILES ({len(test_files)}):")
        print("-" * 50)
        for missing in test_files:
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

    # Print failures
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


def check_rule_id_consistency(rules_with_tests: List[Dict]) -> List[Dict]:
    """Check if rule IDs are consistent between rule files and their info.yml files.
    Also checks if rule IDs match the test file names.

    Returns:
        List of dicts containing information about inconsistent rule IDs
    """
    inconsistent_rules = []

    for rule_info in rules_with_tests:
        rule_id = rule_info["id"]
        info_metadata_rule_id = rule_info.get("info_metadata_rule_id", "")
        rule_path = rule_info["path"]
        tests = rule_info.get("tests", [])

        # Check rule ID vs info.yml rule_metadata[0].id consistency
        if not info_metadata_rule_id:
            inconsistent_rules.append(
                {
                    "rule_id": rule_id,
                    "info_metadata_rule_id": info_metadata_rule_id,
                    "rule_path": rule_path,
                    "issue": "missing_info_metadata_rule_id",
                    "expected": rule_id,
                    "actual": info_metadata_rule_id,
                    "message": "info.yml is missing rule_metadata or rule_metadata[0].id",
                }
            )
        elif rule_id != info_metadata_rule_id:
            inconsistent_rules.append(
                {
                    "rule_id": rule_id,
                    "info_metadata_rule_id": info_metadata_rule_id,
                    "rule_path": rule_path,
                    "issue": "rule_vs_info_metadata_mismatch",
                    "expected": rule_id,
                    "actual": info_metadata_rule_id,
                    "message": f"Rule ID '{rule_id}' in rule file does not match "
                    f"info.yml rule_metadata[0].id '{info_metadata_rule_id}'",
                }
            )

        # Check rule ID vs test file name consistency
        for test in tests:
            test_path = test.get("path", "")
            if test_path:
                # Extract filename without extension
                filename = os.path.basename(test_path)
                name_without_ext = os.path.splitext(filename)[0]
                file_ext = os.path.splitext(filename)[1].lower()

                # Check if the filename (without extension) matches the rule ID
                # Only check for .evtx and .json files (.json is optional conversion of .evtx)
                if file_ext in [".evtx", ".json"] and name_without_ext != rule_id:
                    expected_filename = f"{rule_id}{file_ext}"
                    inconsistent_rules.append(
                        {
                            "rule_id": rule_id,
                            "test_filename": filename,
                            "rule_path": rule_path,
                            "test_path": test_path,
                            "issue": "rule_vs_testfile_mismatch",
                            "expected": expected_filename,
                            "actual": filename,
                            "message": f"Rule ID '{rule_id}' does not match test file"
                            f"name '{name_without_ext}' (expected: {rule_id}{file_ext})",
                        }
                    )

    if inconsistent_rules:
        print("\nERROR: Found rule ID inconsistencies:")
        print("=" * 60)
        print()

        # Group by issue type for better readability
        rule_vs_info_issues = [
            r
            for r in inconsistent_rules
            if r.get("issue")
            in ["rule_vs_info_metadata_mismatch", "missing_info_metadata_rule_id"]
        ]
        rule_vs_testfile_issues = [
            r
            for r in inconsistent_rules
            if r.get("issue") == "rule_vs_testfile_mismatch"
        ]

        if rule_vs_info_issues:
            print("RULE ID vs INFO.YML RULE_METADATA[0].ID MISMATCHES:")
            print("-" * 50)
            for inconsistent in rule_vs_info_issues:
                print(f"Rule file ID: {inconsistent['rule_id']}")
                print(
                    f"Info.yml rule_metadata[0].id: {inconsistent['info_metadata_rule_id']}"
                )
                print(f"Expected: {inconsistent['expected']}")
                print(f"Actual: {inconsistent['actual']}")
                print(f"Rule file: {inconsistent['rule_path']}")
                print(f"Message: {inconsistent['message']}")
                print("-" * 50)
                print()

        if rule_vs_testfile_issues:
            print("RULE ID vs TEST FILE NAME MISMATCHES:")
            print("-" * 40)
            for inconsistent in rule_vs_testfile_issues:
                print(f"Rule ID: {inconsistent['rule_id']}")
                print(f"Expected filename: {inconsistent['expected']}")
                print(f"Actual filename: {inconsistent['actual']}")
                print(f"Rule file: {inconsistent['rule_path']}")
                print(f"Test file: {inconsistent['test_path']}")
                print(f"{inconsistent['message']}")
                print()

        print("<=>" * 20)
        print("Rule IDs must match between:")
        print("1. Rule files ID and their info.yml rule_metadata[0].id")
        print("2. Rule files ID and their test file names (EVTX/JSON files)")
        print("   Note: JSON files are optional conversions of EVTX files")
    return inconsistent_rules


def main():
    """Main function to run regression tests for Sigma rules."""
    args = parse_arguments()
    init_checks(args)

    # Find rules with tests
    print("Scanning for rules with test data...")
    rules_with_tests, missing_files, missing_regression_tests_path = (
        find_rules_with_tests(args.rules_paths, workers=args.workers)
    )

    print(f"Found {len(rules_with_tests)} rule(s) with regression tests configured.\n")

    print("Checking for consistent rule <--> test mapping...")
    inconsistent_rules = check_rule_id_consistency(rules_with_tests)
    if inconsistent_rules:
        sys.exit(1)
    else:
        print("All rules are mapped correctly.")

    validate_missing_tests(args, rules_with_tests, missing_regression_tests_path)
    check_missing_test_files(missing_files)
    print()
    if not rules_with_tests:
        print("No rules with test data found")
        sys.exit(1)

    # Test each rule
    print("Running tests...\n")
    total_tests, passed_tests, failures = run_tests(args, rules_with_tests)

    print_summary(total_tests, passed_tests, failures)

    # Exit with error code if any tests failed
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
