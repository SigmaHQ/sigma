# Test output backends for sigmac
# Copyright 2021 Devo, Inc.
# Author: Eduardo Ocete <eduardo.ocete@devo.com>

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

from sigma.backends.devo import DevoBackend

from sigma.parser.collection import SigmaCollectionParser
from sigma.configuration import SigmaConfiguration

class TestDevoBackend(unittest.TestCase):

    def setUp(self):
        self.basic_rule = {"title": "Devo Backend Test", "level": "testing"}
        self.table = "sourcetable"

    def testPlain(self):
        # Int value
        detection = {"selection1": {"fieldname1": 1},
                    "condition": "selection1"}
        expected_result = 'from {} where fieldname1 = 1 select *'.format(self.table)
        self.validate(detection, expected_result)

        # String value
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1"}
        expected_result = 'from {} where fieldname1 = "value1" select *'.format(self.table)
        self.validate(detection, expected_result)

        # Int array value
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "condition": "selection1"}
        expected_result = 'from {} where has(fieldname1, 1, 2, 3) select *'.format(self.table)
        self.validate(detection, expected_result)

        # String array value
        detection = {"selection1": {"fieldname1": ["value1", "value2", "value3"]},
                     "condition": "selection1"}
        expected_result = 'from {} where has(fieldname1, "value1", "value2", "value3") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Simple and
        detection = {"selection1": {"fieldname1": ["value1", "value2", "value3"],
                                    "fieldname2": "value5"},
                     "condition": "selection1"}
        expected_result = 'from {} where (has(fieldname1, "value1", "value2", "value3") and fieldname2 = "value5") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Selection and
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "selection2": {"fieldname2": "value5"},
                     "condition": "selection1 and selection2"}
        expected_result = 'from {} where (has(fieldname1, 1, 2, 3) and fieldname2 = "value5") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Selection or
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "selection2": {"fieldname2": "value5"},
                     "condition": "selection1 or selection2"}
        expected_result = 'from {} where (has(fieldname1, 1, 2, 3) or fieldname2 = "value5") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Selection one of them
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "selection2": {"fieldname2": "value5"},
                     "condition": "1 of them"}
        expected_result = 'from {} where (has(fieldname1, 1, 2, 3) or fieldname2 = "value5") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Selection all of them
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "selection2": {"fieldname2": "value5"},
                     "condition": "all of them"}
        expected_result = 'from {} where (has(fieldname1, 1, 2, 3) and fieldname2 = "value5") select *'.format(self.table)
        self.validate(detection, expected_result)

        # Negation
        detection = {"selection1": {"fieldname1": [1, 2, 3]},
                     "selection2": {"fieldname2": "value5"},
                     "condition": "selection1 and not selection2"}
        expected_result = 'from {} where (has(fieldname1, 1, 2, 3) and  not (fieldname2 = "value5")) select *'.format(self.table)
        self.validate(detection, expected_result)


    def testModifiers(self):
        # Contains
        detection = {"selection1": {"fieldname1|contains": "value1"},
                     "condition": "selection1"}
        expected_result = 'from {} where toktains(fieldname1, "value1", true, true) select *'.format(self.table)
        self.validate(detection, expected_result)

        # StartsWith
        detection = {"selection1": {"fieldname1|startswith": "value1"},
                     "condition": "selection1"}
        expected_result = 'from {} where matches(fieldname1, nameglob("value1*")) select *'.format(self.table)
        self.validate(detection, expected_result)

        # EndsWith
        detection = {"selection1": {"fieldname1|endswith": "value1"},
                     "condition": "selection1"}
        expected_result = 'from {} where matches(fieldname1, nameglob("*value1")) select *'.format(self.table)
        self.validate(detection, expected_result)

        # All
        detection = {"selection1": {"fieldname1|all": ["value1", "value2"]},
                     "condition": "selection1"}
        expected_result = 'from {} where (fieldname1 = "value1" and fieldname1 = "value2") select *'.format(self.table)
        self.validate(detection, expected_result)

    def testAggregations(self):
        # Count
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | count() > 1"}
        expected_result = 'from {} where fieldname1 = "value1" select count(*) as agg where agg > 1 select *'.format(self.table)
        self.validate(detection, expected_result)

        # Min
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | min(fieldname2) by fieldname3 > 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select min(fieldname2) as agg where agg > 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # Max
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | max(fieldname2) by fieldname3 > 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select max(fieldname2) as agg where agg > 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # Avg
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | avg(fieldname2) by fieldname3 > 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select avg(fieldname2) as agg where agg > 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # sum
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | sum(fieldname2) by fieldname3 > 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select sum(fieldname2) as agg where agg > 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # <
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | sum(fieldname2) by fieldname3 < 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select sum(fieldname2) as agg where agg < 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # ==
        detection = {"selection1": {"fieldname1": "value1"},
                     "condition": "selection1 | sum(fieldname2) by fieldname3 == 5"}
        expected_result = 'from {} where fieldname1 = "value1" group by fieldname3 select sum(fieldname2) as agg where agg == 5 select *'.format(self.table)
        self.validate(detection, expected_result)

        # Multiple conditions
        detection = {"selection1": {"fieldname1": "value1"},
                     "selection2": {"fieldname2": "*", "fieldname3": "*"},
                     "condition": "selection1 or selection2 | count(fieldname4) by fieldname5 > 3"}
        expected_result = 'from {} where (fieldname1 = "value1" or (matches(fieldname2, nameglob("*")) and matches(fieldname3, nameglob("*")))) group by fieldname5 select count(fieldname4) as agg where agg > 3 select *'.format(self.table)
        self.validate(detection, expected_result)

    def testFullTextSearch(self):
        # Single str FTS
        detection = {"selection1": ["value1"],
                     "condition": "selection1"}
        expected_result = 'from {} where weaktoktains(raw, "value1", true, true) select *'.format(self.table)
        self.validate(detection, expected_result)

        # OR node FTS
        detection = {"selection1": {"fieldname1": "value1"},
                     "selection2|contains": ["value2", "value3"],
                     "condition": "1 of them"}
        expected_result = 'from {} where (fieldname1 = "value1" or weaktoktains(raw, "value2", true, true) or weaktoktains(raw, "value3", true, true)) select *'.format(self.table)
        self.validate(detection, expected_result)

    def testRegex(self):
        # Arrange
        detection = {"selection1": {"fieldname1|re": "([0-9]|[1-9][0-9]|[1-4][0-9]{2})"},
                     "condition": "selection1"}
        expected_result = 'from ' + self.table + ' where matches(fieldname1, re(\"([0-9]|[1-9][0-9]|[1-4][0-9]{2})\")) select *'

        # Act & Assert
        self.validate(detection, expected_result)

    def testDerivedFields(self):
        # Arrange
        detection = {"selection1": {"select func(fieldname1) as fieldname1": "value1"},
                     "condition": "selection1"}
        expected_result = 'from ' + self.table + \
                          ' select func(fieldname1) as fieldname1 where fieldname1 = "value1" select *'
        # Act & Assert
        self.validate(detection, expected_result)

    def testNearNotSupported(self):
        # Arrange
        detection = {"selection1": {"fieldname1": "value1"},
                     "selection2": {"fieldname2": "value2"},
                     "condition": "selection1 | near selection1 and selection2"}
        expected_result = NotImplementedError()

        # Act & Assert
        self.validate(detection, expected_result)


    def validate(self, detection, expectation):
        config = SigmaConfiguration()

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = DevoBackend(config, self.table)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                if isinstance(expectation, str):
                    self.assertEqual(expectation, backend.generate(p))
                elif isinstance(expectation, Exception):
                    self.assertRaises(type(expectation), backend.generate, p)


if __name__ == '__main__':
    unittest.main()
