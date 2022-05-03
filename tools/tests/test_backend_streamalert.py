# Output backends for sigmac
# Copyright 2022 AlertIQ.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import yaml
import argparse

from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from sigma.backends.streamalert import StreamAlertQueryBackend


if __name__ == "__main__":
    """
    You can see the StreamAlert backend rules coverage by running:
    cd tools/
    python3 -m tests.test_backend_streamalert
    """
    parser = argparse.ArgumentParser(
        description="Test the StreamAlert backend over all the Sigma rules in the repository."
    )
    parser.add_argument(
        "--verbose",
        default=False,
        action="store_true",
        help="Print individual results about each processed rule.",
    )

    args = parser.parse_args()

    verbose_report = args.verbose

    skipped = 0
    errors = 0
    successes = 0
    total = 0

    config = SigmaConfiguration(open('./config/streamalert.yml'))
    backend = StreamAlertQueryBackend(config)

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
                        if verbose_report:
                            print("[SKIPPED] {}: {}".format(rule_path, err))
                            results['skipped'] += "[SKIPPED] {}: {}\n".format(
                                rule_path, err
                            )
                        skipped += 1
                    except BaseException as err:
                        if verbose_report:
                            print("[FAILED] {}: {}".format(rule_path, err))
                            results['failed'] += "[FAILED] {}: {}\n".format(
                                rule_path, err
                            )
                        errors += 1
                    else:
                        queries += '\n# {}\n{}\n'.format(rule_path, query)
                        if verbose_report:
                            print("[OK] {}".format(rule_path))
                            results['success'] += "[OK] {}\n".format(rule_path)
                        successes += 1

    print("\n==========Statistics==========\n")
    print(
        "SUCCESSES: {}/{} ({:.2f}%)".format(successes, total, successes / total * 100)
    )
    print("SKIPPED: {}/{} ({:.2f}%)".format(skipped, total, skipped / total * 100))
    print("ERRORS: {}/{} ({:.2f}%)".format(errors, total, errors / total * 100))
    print("\n==============================\n")

    # open('not_implemented.txt', 'w').write(results['skipped'])
    # open('exeptions.txt', 'w').write(results['failed'])
    # open('success.txt', 'w').write(results['success'])
    # open('success.py', 'w').write(queries)
