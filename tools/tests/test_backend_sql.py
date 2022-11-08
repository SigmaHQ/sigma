# Test output backends for sigmac
# Copyright 2020 Jonas Hagg

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

import unittest
from unittest.mock import patch

from sigma.backends.sql import SQLBackend

from sigma.parser.collection import SigmaCollectionParser
from sigma.config.mapping import FieldMapping
from sigma.configuration import SigmaConfiguration

class TestGenerateQuery(unittest.TestCase):

    def setUp(self):
        self.basic_rule = {"title": "Test", "level": "testing"}
        self.table = "eventlog"

    def test_regular_queries(self):
        # Test regular queries
        detection = {"selection": {"fieldname": "test1"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname = "test1"'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": 4}, "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname = "4"'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": [
            "test1", "test2"]}, "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname IN ("test1", "test2")'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {
            "fieldname": [3, 4]}, "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname IN ("3", "4")'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1", "fieldname2": [
            "test2", "test3"]}, "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname1 = "test1" AND fieldname2 IN ("test2", "test3"))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection and filter"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname = "test1" AND fieldname2 = "whatever")'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection or filter"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname = "test1" OR fieldname2 = "whatever")'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection and not filter"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname = "test1" AND NOT (fieldname2 = "whatever"))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1"}, "filter": {
            "fieldname2": "test2"}, "condition": "1 of them"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname1 = "test1" OR fieldname2 = "test2")'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1"}, "filter": {
            "fieldname2": "test2"}, "condition": "all of them"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname1 = "test1" AND fieldname2 = "test2")'.format(
            self.table)
        self.validate(detection, expected_result)

    def test_modifiers(self):

        # contains
        detection = {"selection": {"fieldname|contains": "test"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE "%test%" ESCAPE \'\\\''.format(
            self.table)
        self.validate(detection, expected_result)

        # all
        detection = {"selection": {"fieldname|all": [
            "test1", "test2"]}, "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE (fieldname = "test1" AND fieldname = "test2")'.format(
            self.table)
        self.validate(detection, expected_result)

        # endswith
        detection = {"selection": {"fieldname|endswith": "test"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE "%test" ESCAPE \'\\\''.format(
            self.table)
        self.validate(detection, expected_result)

        # startswith
        detection = {"selection": {"fieldname|startswith": "test"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE "test%" ESCAPE \'\\\''.format(
            self.table)
        self.validate(detection, expected_result)

    def test_aggregations(self):

        # count
        detection = {"selection": {"fieldname": "test"},
                     "condition": "selection | count() > 5"}
        inner_query = 'SELECT *,count(*) AS agg FROM {} WHERE fieldname = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # min
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | min(fieldname2) > 5"}
        inner_query = 'SELECT *,min(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # max
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | max(fieldname2) > 5"}
        inner_query = 'SELECT *,max(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # avg
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | avg(fieldname2) > 5"}
        inner_query = 'SELECT *,avg(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # sum
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | sum(fieldname2) > 5"}
        inner_query = 'SELECT *,sum(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # <
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | sum(fieldname2) < 5"}
        inner_query = 'SELECT *,sum(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg < 5'.format(inner_query)
        self.validate(detection, expected_result)

        # ==
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | sum(fieldname2) == 5"}
        inner_query = 'SELECT *,sum(fieldname2) AS agg FROM {} WHERE fieldname1 = "test"'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

        # group by
        detection = {"selection": {"fieldname1": "test"},
                     "condition": "selection | sum(fieldname2) by fieldname3 == 5"}
        inner_query = 'SELECT *,sum(fieldname2) AS agg FROM {} WHERE fieldname1 = "test" GROUP BY fieldname3'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

        # multiple conditions
        detection = {"selection": {"fieldname1": "test"}, "filter": {
            "fieldname2": "tessst"}, "condition": "selection OR filter | sum(fieldname2) == 5"}
        inner_query = 'SELECT *,sum(fieldname2) AS agg FROM {} WHERE (fieldname1 = "test" OR fieldname2 = "tessst")'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

    def test_wildcards(self):

        # wildcard: *
        detection = {"selection": {"fieldname": "test*"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # wildcard: ?
        detection = {"selection": {"fieldname": "test?"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test_"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # escaping:
        detection = {"selection": {"fieldname": r"test\?"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\?"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\\*"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\\%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\*"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\*"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\\"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\\"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\abc"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\\abc"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test%"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test_"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE fieldname LIKE '.format(
            self.table) + r'"test\_"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # multiple options
        detection = {"selection": {"fieldname": [
            "test*", "*test"]}, "condition": "selection"}
        opt1 = 'fieldname LIKE ' + r'"test%"' + r" ESCAPE '\'"
        opt2 = 'fieldname LIKE ' + r'"%test"' + r" ESCAPE '\'"
        expected_result = 'SELECT * FROM {} WHERE ({} OR {})'.format(
            self.table, opt1, opt2)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname|all": [
            "test*", "*test"]}, "condition": "selection"}
        opt1 = 'fieldname LIKE ' + r'"test%"' + r" ESCAPE '\'"
        opt2 = 'fieldname LIKE ' + r'"%test"' + r" ESCAPE '\'"
        expected_result = 'SELECT * FROM {} WHERE ({} AND {})'.format(
            self.table, opt1, opt2)
        self.validate(detection, expected_result)

    def test_fieldname_mapping(self):
        detection = {"selection": {"fieldname": "test1"},
                     "condition": "selection"}
        expected_result = 'SELECT * FROM {} WHERE mapped_fieldname = "test1"'.format(
            self.table)

        # configure mapping
        config = SigmaConfiguration()
        config.fieldmappings["fieldname"] = FieldMapping(
            "fieldname", "mapped_fieldname")

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = SQLBackend(config, self.table)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                self.assertEqual(expected_result, backend.generate(p))

    def test_not_implemented(self):
        # near aggregation not implemented
        detection = {"selection": {"fieldname": "test"}, "filter": {
            "fieldname": "test2"}, "condition": "selection | near selection and filter"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        # re modifier is not implemented
        detection = {"selection": {"fieldname|re": "test"},
                     "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        #Full Text Search is not implemented
        detection = {"selection": ["test1"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)


    def validate(self, detection, expectation):

        config = SigmaConfiguration()

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = SQLBackend(config, self.table)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                if isinstance(expectation, str):
                    self.assertEqual(expectation, backend.generate(p))
                elif isinstance(expectation, Exception):
                    self.assertRaises(type(expectation), backend.generate, p)


if __name__ == '__main__':
    unittest.main()
