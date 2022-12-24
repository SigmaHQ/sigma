# Output backends for sigmac
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

from sigma.backends.sql import SQLBackend
from sigma.parser.condition import NodeSubexpression, ConditionAND, ConditionOR, ConditionNOT
import re


class SQLiteBackend(SQLBackend):
    """Converts Sigma rule into SQL query for SQLite"""
    identifier = "sqlite"
    active = True

    mapFullTextSearch = "%s MATCH ('\"%s\"')"

    def __init__(self, sigmaconfig, table):
        super().__init__(sigmaconfig, table)
        self.mappingItem = False

    def requireFTS(self, node):
        return (not self.mappingItem and
                (type(node) in (int, str) or all(isinstance(val, str) for val in node) or all(isinstance(val, int) for val in node)))

    def generateFTS(self, value):
        if re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", value):
            raise NotImplementedError(
                "Wildcards in SQlite Full Text Search not implemented")
        self.countFTS += 1
        return self.mapFullTextSearch % (self.table, value)

    def generateANDNode(self, node):

        if self.requireFTS(node):
            fts = str('"' + self.andToken + '"').join(self.cleanValue(val)
                                                      for val in node)
            return self.generateFTS(fts)

        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):

        if self.requireFTS(node):
            fts = str('"' + self.orToken + '"').join(self.cleanValue(val)
                                                     for val in node)
            return self.generateFTS(fts)

        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateMapItemNode(self, node):
        try:
            self.mappingItem = True
            fieldname, value = node
            transformed_fieldname = self.fieldNameMapping(fieldname, value)

            has_wildcard = re.search(
                r"((\\(\*|\?|\\))|\*|\?|_|%)", self.generateNode(value))

            if "," in self.generateNode(value) and not has_wildcard:
                return self.mapMulti % (transformed_fieldname, self.generateNode(value))
            elif "LENGTH" in transformed_fieldname:
                return self.mapLength % (transformed_fieldname, value)
            elif type(value) == list:
                return self.generateMapItemListNode(transformed_fieldname, value)
            elif self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):

                if has_wildcard:
                    return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
                else:
                    return self.mapExpression % (transformed_fieldname, self.generateNode(value))

            elif "sourcetype" in transformed_fieldname:
                return self.mapSource % (transformed_fieldname, self.generateNode(value))
            elif has_wildcard:
                return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
            else:
                raise TypeError(
                    "Backend does not support map values of type " + str(type(value)))
        finally:
            self.mappingItem = False

    def generateValueNode(self, node):
        if self.mappingItem:
            return self.valueExpression % (self.cleanValue(str(node)))
        else:
            return self.generateFTS(self.cleanValue(str(node)))

    def generateQuery(self, parsed):
        self.countFTS = 0
        result = self.generateNode(parsed.parsedSearch)
        if self.countFTS > 1:
            raise NotImplementedError(
                "Match operator ({}) is allowed only once in SQLite, parse rule in a different way:\n{}".format(self.countFTS, result))
        self.countFTS = 0

        if parsed.parsedAgg:
            # Handle aggregation
            fro, whe = self.generateAggregation(parsed.parsedAgg, result)
            return "SELECT * FROM {} WHERE {}".format(fro, whe)

        return "SELECT * FROM {} WHERE {}".format(self.table, result)
