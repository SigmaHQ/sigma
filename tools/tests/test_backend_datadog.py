import os
import yaml

import unittest

from sigma.configuration import SigmaConfiguration
from sigma.parser.rule import SigmaParser
from sigma.config.mapping import FieldMapping
from sigma.backends.datadog import DatadogLogsBackend


class TestDatadogBackend(unittest.TestCase):
    """Test cases for the Datadog backend."""

    def setUp(self):
        self.basic_rule = {
            "detection": {"selection": {"attribute": "test"}, "condition": "selection"}
        }

    def generate_query(
        self, rule, backend_options=dict(), config=dict(), fieldmappings=dict()
    ):
        cfg = SigmaConfiguration()
        cfg.config = config
        cfg.fieldmappings = fieldmappings
        backend = DatadogLogsBackend(cfg, backend_options)
        parser = SigmaParser(rule, cfg)

        return backend.generate(parser)

    def test_all_sigma_rules(self):
        """Test the Datadog backend over all the Sigma rules in the repository."""

        skipped = 0
        errors = 0
        successes = 0
        total = 0

        config = SigmaConfiguration()
        backend = DatadogLogsBackend(config)

        for (dirpath, _, filenames) in os.walk("../rules"):
            for filename in filenames:
                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    with self.subTest(filename):
                        rule_path = os.path.join(dirpath, filename)

                        with open(rule_path, "r") as rule_file:
                            total += 1
                            parser = SigmaParser(yaml.safe_load(rule_file), config)

                            try:
                                query = backend.generate(parser)
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

    def test_attribute(self):
        query = self.generate_query(self.basic_rule)
        expected_query = "@attribute:test"
        self.assertEqual(query, expected_query)

    def test_facets_backend_option(self):
        query = self.generate_query(
            self.basic_rule, backend_options={"index": "test_index"}
        )
        expected_query = "index:test_index AND @attribute:test"
        self.assertEqual(query, expected_query)

    def test_facets_config(self):
        self.basic_rule["detection"]["selection"]["test-facet"] = "myfacet"
        query = self.generate_query(self.basic_rule, config={"facets": ["test-facet"]})
        expected_query = "@attribute:test AND test-facet:myfacet"
        self.assertEqual(query, expected_query)

    def test_special_characters_escape(self):
        self.basic_rule["detection"]["selection"][
            "regex-attribute"
        ] = "anything?inbetween"
        query = self.generate_query(self.basic_rule)
        expected_query = "@attribute:test AND @regex-attribute:anything\\?inbetween"
        self.assertEqual(query, expected_query)

    def test_space_escape(self):
        self.basic_rule["detection"]["selection"]["space-attribute"] = "with space"
        query = self.generate_query(self.basic_rule)
        expected_query = "@attribute:test AND @space-attribute:with?space"
        self.assertEqual(query, expected_query)

    def test_space_escape(self):
        query = self.generate_query(
            self.basic_rule,
            fieldmappings={"attribute": FieldMapping("attribute", "another_attribute")},
        )
        expected_query = "@another_attribute:test"
        self.assertEqual(query, expected_query)
