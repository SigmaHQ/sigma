import argparse
import json
import os
import subprocess
import sys
import yaml
from typing import Dict, List


# This script works with the new Sigma rule format where rules contain a
# 'regression_tests_path' field pointing to an info.yml file that contains
# test metadata and EVTX file paths in the 'regression_tests_info' section.


def find_rules_with_tests(rules_paths: List[str]) -> List[Dict]:
    """Find all rules that have a 'regression_tests_path' attribute pointing to test info files."""
    results = []

    for rules_path in rules_paths:
        if not os.path.exists(rules_path):
            print(f"Warning: Rules path {rules_path} does not exist")
            continue

        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            rule_data = yaml.safe_load(f)

                        if rule_data and "regression_tests_path" in rule_data:
                            rule_id = rule_data.get("id", "unknown")
                            regression_tests_path = rule_data.get("regression_tests_path", "")
                            
                            # Convert relative path to absolute path
                            if not os.path.isabs(regression_tests_path):
                                # Normalize path separators
                                regression_tests_path = regression_tests_path.replace('/', os.sep).replace('\\', os.sep)
                                # Assume path is relative to the workspace root
                                workspace_root = os.path.dirname(os.path.dirname(file_path))
                                while not os.path.exists(os.path.join(workspace_root, regression_tests_path)):
                                    parent = os.path.dirname(workspace_root)
                                    if parent == workspace_root:  # Reached filesystem root
                                        break
                                    workspace_root = parent
                                regression_tests_path = os.path.join(workspace_root, regression_tests_path)
                            
                            if not os.path.exists(regression_tests_path):
                                print(f"Warning: Regression tests info file not found: {regression_tests_path}")
                                continue
                                
                            # Load the info.yml file
                            try:
                                with open(regression_tests_path, "r", encoding="utf-8") as f:
                                    info_data = yaml.safe_load(f)
                                
                                if not info_data or "regression_tests_info" not in info_data:
                                    print(f"Warning: No regression_tests_info found in {regression_tests_path}")
                                    continue
                                
                                # Extract test data from regression_tests_info
                                test_data = []
                                regression_tests = info_data.get("regression_tests_info", [])
                                
                                for test in regression_tests:
                                    if isinstance(test, dict):
                                        test_path = test.get("path", "")
                                        
                                        # Convert relative test path to absolute path
                                        if not os.path.isabs(test_path):
                                            # Normalize path separators
                                            test_path = test_path.replace('/', os.sep).replace('\\', os.sep)
                                            info_dir = os.path.dirname(regression_tests_path)
                                            workspace_root = info_dir
                                            while not os.path.exists(os.path.join(workspace_root, test_path)):
                                                parent = os.path.dirname(workspace_root)
                                                if parent == workspace_root:  # Reached filesystem root
                                                    break
                                                workspace_root = parent
                                            test_path = os.path.join(workspace_root, test_path)
                                        
                                        test_data.append(
                                            {
                                                "type": test.get("type", "unknown"),
                                                "path": test_path,
                                                "name": test.get("name", "Unnamed Test"),
                                                "provider": test.get("provider", ""),
                                            }
                                        )

                                if test_data:
                                    results.append(
                                        {
                                            "path": file_path,
                                            "id": rule_id,
                                            "tests": test_data,
                                        }
                                    )
                                    
                            except Exception as e:
                                print(f"Warning: Could not parse info file {regression_tests_path}: {e}")

                    except Exception as e:
                        print(f"Warning: Could not parse {file_path}: {e}")

    return results
def run_evtx_checker(
    rule_path: str, rule_id: str, test_data: Dict, evtx_checker_path: str, thor_config: str
) -> tuple[bool, str]:
    """Run evtx-sigma-checker and check if rule ID is in output."""
    evtx_path = test_data["path"]

    if not os.path.exists(evtx_path):
        print(f"  Warning: EVTX file {evtx_path} does not exist")
        return False, ""

    cmd = [
        evtx_checker_path,
        "--log-source",
        thor_config,
        "--evtx-path",
        evtx_path,
        "--rule-path",
        os.path.dirname(rule_path),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            print(f"  Warning: evtx-sigma-checker failed: {result.stderr}")
            return False, ""

        # Check if rule ID appears in output
        output_lines = result.stdout.strip().splitlines()
        found_match = False
        match_output = ""
        
        for line in output_lines:
            try:
                json_obj = json.loads(line)
                if json_obj.get("RuleId") == rule_id:
                    found_match = True
                    match_output = line
                    break
            except json.JSONDecodeError:
                # Skip lines that aren't valid JSON
                print(f"  Warning: Skipping non-JSON line: {line}")
                continue

        return found_match, match_output

    except subprocess.TimeoutExpired:
        print(f"  Timeout: evtx-sigma-checker timed out")
        return False, ""
    except Exception as e:
        print(f"  Error running evtx-sigma-checker: {e}")
        return False, ""


def run_test(
    rule_path: str,
    rule_id: str,
    test_data: Dict,
    evtx_checker_path: str,
    thor_config: str,
) -> tuple[bool, str]:
    """Run a test based on its type."""
    test_type = test_data.get("type", "unknown")

    if test_type == "evtx":
        return run_evtx_checker(rule_path, rule_id, test_data, evtx_checker_path, thor_config)
    else:
        print(f"  Warning: Unknown test type '{test_type}', skipping")
        return False, ""

def main():
    parser = argparse.ArgumentParser(
        description="Run true positive tests for Sigma rules with regression_tests_path"
    )

    parser.add_argument(
        "--rules-paths", required=True, help="Comma-separated paths to rule directories"
    )

    parser.add_argument(
        "--evtx-checker", required=True, help="Path to evtx-sigma-checker binary"
    )

    parser.add_argument(
        "--thor-config", required=True, help="Path to thor.yml configuration file"
    )

    args = parser.parse_args()

    # Parse comma-separated rules paths
    rules_paths = [path.strip() for path in args.rules_paths.split(",")]

    print("Starting True Positive Tests...")
    print(f"Rules paths: {rules_paths}")
    print(f"EVTX checker: {args.evtx_checker}")
    print(f"Thor config: {args.thor_config}")
    print()

    # Check if evtx-sigma-checker exists
    if not os.path.exists(args.evtx_checker):
        print(f"Error: evtx-sigma-checker not found at {args.evtx_checker}")
        sys.exit(1)

    # Check if thor config exists
    if not os.path.exists(args.thor_config):
        print(f"Error: Thor config not found at {args.thor_config}")
        sys.exit(1)

    # Find rules with tests
    print("Scanning for rules with test data...")
    rules_with_tests = find_rules_with_tests(rules_paths)
    print(f"Found {len(rules_with_tests)} rules with test data")
    print()

    if not rules_with_tests:
        print("No rules with test data found")
        return

    # Test each rule
    total_tests = 0
    passed_tests = 0
    failures = []

    for rule_info in rules_with_tests:
        rule_path = rule_info["path"]
        rule_id = rule_info["id"]
        tests = rule_info["tests"]

        print(f"\n\nTesting rule: {rule_id}")
        print(f"  File: {rule_path}")

        for i, test_data in enumerate(tests):
            test_name = test_data.get("name", f"Test {i+1}")
            test_type = test_data.get("type", "unknown")
            test_path = test_data.get("path", "unknown")

            print(f"  {test_name} (type: {test_type}): {test_path}")
            total_tests += 1

            success, output = run_test(
                rule_path, rule_id, test_data, args.evtx_checker, args.thor_config
            )

            if success:
                passed_tests += 1
                print(f"    ✓ PASS - Match found for Rule ID: {rule_id}\n")
                print(f"    Output: {output}\n\n")
            else:
                failures.append(
                    {
                        "rule_id": rule_id,
                        "rule_path": rule_path,
                        "test_name": test_name,
                        "test_type": test_type,
                        "test_path": test_path,
                        "test_number": i + 1,
                    }
                )
                print(f"    ✗ FAIL")
        print()

    # Print summary
    print("=" * 60)
    print("TRUE POSITIVE TEST SUMMARY")
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

    # Exit with error code if any tests failed
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
