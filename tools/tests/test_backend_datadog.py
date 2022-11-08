# Output backends for sigmac
# Copyright 2021 Datadog, Inc.

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

import unittest

from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from sigma.config.mapping import FieldMapping
from sigma.backends.datadog import DatadogLogsBackend


class TestDatadogLogsBackend(unittest.TestCase):
    """Test cases for the Datadog Logs backend."""

    def generate_query(self, rule, backend_options=None, config=None, fieldmappings=None):
        if backend_options is None:
            backend_options = {}

        if config is None:
            config = {}

        if fieldmappings is None:
            fieldmappings = {}

        cfg = SigmaConfiguration()
        cfg.config = config
        cfg.fieldmappings = fieldmappings
        backend = DatadogLogsBackend(cfg, backend_options)
        parser = SigmaParser(rule, cfg)

        return backend.generate(parser)

    def generate_basic_rule(self):
        return {
            "detection": {"selection": {"attribute": "test"}, "condition": "selection"}
        }

    def test_attribute(self):
        query = self.generate_query(self.generate_basic_rule())
        expected_query = "@attribute:test"
        self.assertEqual(query, expected_query)

    def test_tags_backend_option(self):
        query = self.generate_query(
            self.generate_basic_rule(), backend_options={"index": "test_index"}
        )
        expected_query = "index:test_index AND @attribute:test"
        self.assertEqual(query, expected_query)

    def test_tags_config(self):
        rule = {
            "detection": {
                "selection": {"attribute": "test", "test-tag": "mytag"},
                "condition": "selection",
            }
        }
        query = self.generate_query(rule, config={"tags": {"test-tag":"test-tag2"}})
        expected_query = "@attribute:test AND test-tag2:mytag"
        self.assertEqual(query, expected_query)

    def test_special_characters_escape(self):
        rule = {
            "detection": {
                "selection": {
                    "attribute": "test",
                    "regex-attribute": "anything!inbetween",
                },
                "condition": "selection",
            }
        }
        query = self.generate_query(rule)
        expected_query = """@attribute:test AND @regex-attribute:anything\\!inbetween"""
        self.assertEqual(query, expected_query)

    def test_space_escape(self):
        rule = {
            "detection": {
                "selection": {
                    "attribute": "test",
                    "space-attribute": "with space",
                },
                "condition": "selection",
            }
        }
        query = self.generate_query(rule)
        expected_query = "@attribute:test AND @space-attribute:with?space"
        self.assertEqual(query, expected_query)

    def test_field_mappings(self):
        query = self.generate_query(
            self.generate_basic_rule(),
            fieldmappings={"attribute": FieldMapping("attribute", "another_attribute")},
        )
        expected_query = "@another_attribute:test"
        self.assertEqual(query, expected_query)

    def test_list_selection(self):
        rule = {
            "detection": {
                "selection": {
                    "attribute": "test",
                    "list-attribute": [
                        "a",
                        "b",
                    ],
                },
                "condition": "selection",
            }
        }
        query = self.generate_query(rule)
        expected_query = "@attribute:test AND @list-attribute:(a OR b)"
        self.assertEqual(query, expected_query)


if __name__ == "__main__":
    """
    Run the Datadog backend over all the Sigma rules in the repository.
    You can run the script simply with: `python3 -m tests.test_backend_datadog`
    from the `tools/` directory.
    """
    parser = argparse.ArgumentParser(description="Test the Datadog backend over all the Sigma rules in the repository.")
    parser.add_argument("--verbose", default=False, action="store_true", help="Print individual results about each processed rule.")

    args = parser.parse_args()

    verbose_report = args.verbose

    skipped = 0
    errors = 0
    successes = 0
    total = 0

    config = SigmaConfiguration()
    backend = DatadogLogsBackend(config)

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
                        skipped += 1
                    except BaseException as err:
                        if verbose_report:
                            print("[FAILED] {}: {}".format(rule_path, err))
                        errors += 1
                    else:
                        if verbose_report:
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
