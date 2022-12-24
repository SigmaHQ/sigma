import os
import yaml
import argparse

from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from sigma.backends.dnif import DnifBackend


if __name__ == "__main__":
    """
    You can see the dnif backend rules coverage by running:
    cd tools/
    python3 -m tests.test_backend_dnif
    """

    parser = argparse.ArgumentParser(description="Test the DNIF backend over all the Sigma rules in the repository.")
    parser.add_argument("--success", "-S", default=False, action="store_true",
                        help="Print only success results about each processed rule.")
    parser.add_argument("--skipped", "-s", default=False, action="store_true",
                        help="Print only skipped results about each processed rule.")
    parser.add_argument("--failed", "-f", default=False, action="store_true",
                        help="Print only failed results about each processed rule.")

    args = parser.parse_args()

    success_report = args.success
    skipped_report = args.skipped
    failed_report = args.failed
    display_results = False

    if success_report or skipped_report or failed_report:
        display_results = True

    skipped = 0
    errors = 0
    successes = 0
    total = 0

    config = SigmaConfiguration(open('./config/dnif.yml'))
    backend = DnifBackend(config)

    results = {'skipped': '', 'failed': '', 'success': ''}
    queries = ''

    for (dirpath, _, filenames) in os.walk("../rules"):
        for filename in filenames:
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                rule_path = os.path.join(dirpath, filename)

                with open(rule_path, "r") as rule_file:
                    total += 1
                    parser = SigmaParser(yaml.safe_load(rule_file), config)

                    try:
                        query = backend.generate(parser)
                    except NotImplementedError as err:
                        results['skipped'] += "[SKIPPED] {}: {}\n".format(
                            rule_path, err
                        )
                        skipped += 1
                    except BaseException as err:
                        results['failed'] += "[FAILED] {}: {}\n".format(
                            rule_path, err
                        )
                        errors += 1
                    else:
                        queries += '\n# {}\n{}\n'.format(rule_path, query)
                        results['success'] += "[OK] {}\n".format(rule_path)
                        successes += 1

    print("\n==========Statistics==========\n")
    print(
        "SUCCESSES: {}/{} ({:.2f}%)".format(successes, total, successes / total * 100)
    )
    print("SKIPPED: {}/{} ({:.2f}%)".format(skipped, total, skipped / total * 100))
    print("FAILED: {}/{} ({:.2f}%)".format(errors, total, errors / total * 100))
    print("\n==============================\n")

    if display_results:
        print("\n==========Results==========\n")
        if success_report:
            if results['success']:
                print(f"SUCCESS RULES:\n{results['success']}")
            else:
                print(f"SUCCESS RULES: No Results to Display")
        elif skipped_report:
            if results['skipped']:
                print(f"SKIPPED RULES:\n{results['skipped']}")
            else:
                print(f"SKIPPED RULES: No Results to Display")
        elif failed_report:
            if results['failed']:
                print(f"FAILED RULES:\n{results['failed']}")
            else:
                print(f"FAILED RULES: No Results to Display")
