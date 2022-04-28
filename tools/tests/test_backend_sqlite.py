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

from sigma.backends.sqlite import SQLiteBackend

from sigma.parser.collection import SigmaCollectionParser
from sigma.config.mapping import FieldMapping
from sigma.configuration import SigmaConfiguration

class TestFullTextSearch(unittest.TestCase):

    def setUp(self):
        self.basic_rule = {"title": "Test", "level": "testing"}
        self.table = "eventlog"

    def test_full_text_search(self):
        detection = {"selection": ["test1"], "condition": "selection"}
        expected_result = 'SELECT * FROM {0} WHERE {0} MATCH (\'"test1"\')'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": [5], "condition": "selection"}
        expected_result = 'SELECT * FROM {0} WHERE {0} MATCH (\'"5"\')'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1", "test2"], "condition": "selection"}
        expected_result = 'SELECT * FROM {0} WHERE ({0} MATCH (\'"test1" OR "test2"\'))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter":["test2"], "condition": "selection and filter"}
        expected_result = 'SELECT * FROM {0} WHERE ({0} MATCH (\'"test1" AND "test2"\'))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": [5, 6], "condition": "selection"}
        expected_result = 'SELECT * FROM {0} WHERE ({0} MATCH (\'"5" OR "6"\'))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter": [
            "test2"], "condition": "selection or filter"}
        expected_result = 'SELECT * FROM {0} WHERE ({0} MATCH (\'"test1" OR "test2"\'))'.format(
            self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter": [
            "test2"], "condition": "selection and filter"}
        expected_result = 'SELECT * FROM {0} WHERE ({0} MATCH (\'"test1" AND "test2"\'))'.format(
            self.table)
        self.validate(detection, expected_result)

    def test_full_text_search_aggregation(self):
        # aggregation with fts
        detection = {"selection": ["test"],
                     "condition": "selection | count() > 5"}
        inner_query = 'SELECT *,count(*) AS agg FROM {0} WHERE {0} MATCH (\'"test"\')'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1", "test2"],
                     "condition": "selection | count() > 5"}
        inner_query = 'SELECT *,count(*) AS agg FROM {0} WHERE ({0} MATCH (\'"test1" OR "test2"\'))'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # aggregation + group by + fts
        detection = {"selection": ["test1", "test2"],
                     "condition": "selection | count() by fieldname > 5"}
        inner_query = 'SELECT *,count(*) AS agg FROM {0} WHERE ({0} MATCH (\'"test1" OR "test2"\')) GROUP BY fieldname'.format(
            self.table)
        expected_result = 'SELECT * FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

    def test_not_implemented(self):
        # fts not implemented with wildcards
        detection = {"selection": ["test*"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test?"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test\\"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)


        # fts is not implemented for nested conditions
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter"}  # this is ok
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection or filter"}  # this is ok
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and not filter"}  # this is already nested
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter and filter"}  # this is nested
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter or filter"}  # this is nested
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

    def validate(self, detection, expectation):

        config = SigmaConfiguration()

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = SQLiteBackend(config, self.table)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                if isinstance(expectation, str):
                    self.assertEqual(expectation, backend.generate(p))
                elif isinstance(expectation, Exception):
                    self.assertRaises(type(expectation), backend.generate, p)

if __name__ == '__main__':
    unittest.main()