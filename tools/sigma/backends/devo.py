# Output backends for sigmac
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

import re
from .base import SingleTextQueryBackend
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.parser.condition import SigmaAggregationParser
from sigma.parser.exceptions import SigmaParseError

class DevoBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Devo query."""
    identifier = "devo"
    active = True

    andToken = " and "                            # Token used for linking expressions with logical AND
    orToken = " or "                              # Same for OR
    notToken = " not "                            # Same for NOT
    subExpression = "(%s)"                        # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = "%s"                         # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = ", "                          # Character for separation of list items
    valueExpression = "\"%s\""                    # Expression of values, %s represents value
    intValueExpression = "%s"                     # Expression of int values, %s represents value
    nullExpression = "isnull(%s)"                 # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = "isnotnull(%s)"           # Expression of queries for not null values. %s is field name
    mapExpression = "%s = %s"                     # Syntax for field/value conditions. First %s is fieldname, second is value
    mapMulti = "has(%s, %s)"                      # Syntax for field/value conditions. First %s is fieldname, second is value
    mapWildcard = "matches(%s, nameglob(%s))"     # Syntax for globbing conditions
    mapRe = "matches(%s, %s)"                     # Syntax for regex conditions that already were transformed by SigmaRegularExpressionModifier
    mapContains = "toktains(%s, %s, true, true)"  # Systax for token value searches
    mapListValueExpression = "%s or %s"           # Syntax for field/value condititons where map value is a list
    mapFullTextSearch = "weaktoktains(raw, \"%s\", true, true)"  # Expression for full text searches
    typedValueExpression = {
        SigmaRegularExpressionModifier: "re(\"%s\")",  # Syntax for regular expressions
    }

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    derivedField = re.compile('^select .* as (.+)$')
    derivedFieldSet = set()
    hasMulticondition = False

    def __init__(self, sigmaconfig, options):
        super().__init__(sigmaconfig)
        # Default table name. It is replaced based on the config file
        self.table = "sourcetable"

    def generateANDNode(self, node):
        generated = []
        for val in node:
            if self.requireFTS(val):
                generated.append(self.generateFTS(val))
            else:
                generated.append(self.generateNode(val))

        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = []
        for val in node:
            if self.requireFTS(val):
                generated.append(self.generateFTS(val))
            else:
                generated.append(self.generateNode(val))

        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        if self.requireFTS(node.item):
            generated = self.generateFTS(node.item)
        else:
            generated = self.generateNode(node.item)

        if generated is not None:
            return self.notToken + generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        fieldname, value = node
        transformed_fieldname = self.fieldNameMapping(fieldname, value)

        if not value:
            # Handle value == None
            return self.generateNULLValueNode(transformed_fieldname)

        has_startswith = self.generateNode(value).startswith("\"*")
        has_endswith = self.generateNode(value).endswith("*\"")
        has_contains = has_startswith and has_endswith and len(self.generateNode(value)) > 3  # Covers "*" case

        if type(value) == SigmaRegularExpressionModifier:
            return self.mapRe % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            if has_contains:
                return self.subExpression % self.andToken.join(self.mapContains % (transformed_fieldname, self.generateNode(val[1:-1])) for val in value)
            elif has_startswith or has_endswith:
                return self.generateMapItemListNode(transformed_fieldname, value)
            else:
                return self.mapMulti % (transformed_fieldname, self.generateNode(value))
        elif type(value) in (str, int):
            if has_contains:
                return self.mapContains % (transformed_fieldname, self.generateNode(value[1:-1]))
            elif has_startswith or has_endswith:
                return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
            else:
                return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        else:
            raise TypeError("Devo backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return "(" + (" or ".join([self.mapWildcard % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateValueNode(self, node):
        if type(node) == int:
            return self.intValueExpression % int(node)
        return self.valueExpression % (self.cleanValue(node))

    def generateNULLValueNode(self, fieldname):
        return self.nullExpression % fieldname

    def generateNotNULLValueNode(self, fieldname):
        return self.notNullExpression % fieldname

    def generateTypedValueNode(self, node):
        try:
            return self.typedValueExpression[type(node)] % (self.cleanValue(str(node)))
        except KeyError:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(node.identifier))

    def generateFTS(self, value):
        return self.mapFullTextSearch % self.cleanValue(value)

    def requireFTS(self, value):
        return isinstance(value, str) or isinstance(value, int) or isinstance(value, list)

    def fieldNameMapping(self, field, value):
        # Handle derived fields
        matched = self.derivedField.search(field)
        if matched:
            self.derivedFieldSet.add(field)
            return matched.group(1)
        return field

    def generateAggregation(self, agg, where_clause):
        if not agg:
            return self.table, where_clause

        # Near operator not supported yet
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not implemented for the %s backend" % self.identifier)
        if (agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT or
                agg.aggfunc == SigmaAggregationParser.AGGFUNC_MAX or
                agg.aggfunc == SigmaAggregationParser.AGGFUNC_MIN or
                agg.aggfunc == SigmaAggregationParser.AGGFUNC_SUM or
                agg.aggfunc == SigmaAggregationParser.AGGFUNC_AVG):

            if agg.groupfield:
                if self.hasMulticondition:
                    group_by = " group every - by subquery_link,{0}".format(self.fieldNameMapping(agg.groupfield, None))
                else:
                    group_by = " group by {0}".format(self.fieldNameMapping(agg.groupfield, None))
            else:
                group_by = ""

            if agg.aggfield:
                select = "{}({}) as agg".format(agg.aggfunc_notrans, self.fieldNameMapping(agg.aggfield, None))
            else:
                if agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT:
                    select = "{}(*) as agg".format(agg.aggfunc_notrans)
                else:
                    raise SigmaParseError("For {} aggregation a fieldname needs to be specified".format(agg.aggfunc_notrans))

            if self.derivedFieldSet:
                derivedFieldsStr = " {}".format(" ".join(self.derivedFieldSet))
            else:
                derivedFieldsStr = ""

            if self.hasMulticondition:
                link_select = ' select "link" as subquery_link'
            else:
                link_select = ""

            temp_table = "from {}{} where {}{}{} select {}".format(self.table, derivedFieldsStr, where_clause, link_select, group_by, select)
            agg_condition = "agg {} {}".format(agg.cond_op, agg.condition)

            return temp_table, agg_condition

        raise NotImplementedError("{} aggregation not implemented in Devo Backend".format(agg.aggfunc_notrans))

    def generateQuery(self, parsed):
        if self.requireFTS(parsed.parsedSearch):
            result = self.generateFTS(parsed.parsedSearch)
        else:
            result = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            fro, whe = self.generateAggregation(parsed.parsedAgg, result)
            return "{} where {} select *".format(fro, whe)

        if self.derivedFieldSet:
            derivedFieldsStr = " {}".format(" ".join(self.derivedFieldSet))
        else:
            derivedFieldsStr = ""

        if self.hasMulticondition:
            select = 'select "link" as subquery_link'
        else:
            select = "select *"

        return "from {}{} where {} {}".format(self.table, derivedFieldsStr, result, select)

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        self.derivedFieldSet = set()
        if sigmaparser.get_logsource() and sigmaparser.get_logsource().index:
            self.table = sigmaparser.get_logsource().index[0]
        else:
            self.table = "sourcetable"

        if len(sigmaparser.condparsed) > 1:
            self.hasMulticondition = True
        else:
            self.hasMulticondition = False

        results = []
        for parsed in sigmaparser.condparsed:
            # Multi condition rules are not supported yet, only the first one will be processed
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            results.append(result)

        if self.hasMulticondition:
            prefix = 'from siem.logtrust.alert.info select "link" as subquery_link group every 24h by subquery_link where '
            suffix = " select *"
            for i in range(len(results)):
                results[i] = "subquery_link in ( " + results[i]
                results[i] += ")"

            body = " or ".join(results)

            return prefix + body + suffix

        return results[0]
