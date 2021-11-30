import os
import yaml

import unittest

from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from sigma.backends.datadog import DatadogBackend


class TestDatadogBackend(unittest.TestCase):
    """Test cases for the Datadog backend."""

    def setUp(self):
        self.config = SigmaConfiguration()
        self.backend = DatadogBackend(self.config)

    def test_all_sigma_rules(self):
        """Test the Datadog backend over all the Sigma rules in the repository."""

        skipped = 0
        errors = 0
        successes = 0
        total = 0

        for (dirpath, _, filenames) in os.walk("../rules"):
            for filename in filenames:
                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    with self.subTest(filename):
                        rule_path = os.path.join(dirpath, filename)

                        with open(rule_path, "r") as rule_file:
                            total += 1

                            try:
                                query = self.backend.generate(
                                    SigmaParser(yaml.safe_load(rule_file), self.config)
                                )
                            except NotImplementedError as err:
                                print("[SKIPPED] {}: {}".format(rule_path, err))
                                skipped += 1
                            except BaseException as err:
                                print("[FAILED] {}: {}".format(rule_path, err))
                                errors += 1
                            else:
                                print("[OK] {}".format(rule_path))
                                successes += 1

        print("\n==========Statistics==========\n")
        print(
            "SUCCESSES: {}/{} ({:.2f}%)".format(
                successes, total, successes / total * 100
            )
        )
        print("SKIPPED: {}/{} ({:.2f}%)".format(skipped, total, skipped / total * 100))
        print("ERRORS: {}/{} ({:.2f}%)".format(errors, total, errors / total * 100))
        print("\n==============================\n")
