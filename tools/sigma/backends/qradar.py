# Output backends for sigmac
# Copyright 2018 SOC Prime

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
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class QRadarBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qradar saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qradar"
    active = True
    reEscape = re.compile('(")')
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "\'%s\'"
    keyExpression = "%s"
    nullExpression = "%s is null"
    notNullExpression = "not (%s is null)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    aql_database = "events"

    def cleanKey(self, key):
        if " " in key:
            key = "\"%s\"" % (key)
            return key
        else:
            return key

    def generateMapItemNode(self, node):
        key, value = node
        if key == 'deviceProduct':
            return self.generateValueNode(value)
        if key == 'aql_database':
            return ""
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                self.value = value.replace("*", "%")
                return "%s ilike %s" % (self.cleanKey(key), self.generateNode(value))
            else:
                return self.mapExpression % (self.cleanKey(key), self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if type(item) == str and "*" in item:
                item = item.replace("*", "%")
                itemslist.append('%s ilike %s' % (self.cleanKey(key), self.generateValueNode(item)))
            else:
                itemslist.append('%s = %s' % (self.cleanKey(key), self.generateValueNode(item)))
        return '('+" or ".join(itemslist)+')'

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            self.qradarPrefixAgg = "SELECT %s(%s) as agg_val from %s where" % (agg.aggfunc_notrans, agg.aggfield, self.aql_database)
            self.qradarSuffixAgg = " group by %s having agg_val %s %s" % (agg.aggfield, agg.cond_op, agg.condition)
            return self.qradarPrefixAgg, self.qradarSuffixAgg
        else:
            self.qradarPrefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, agg.aggfield, self.aql_database)
            self.qradarSuffixAgg = " group by %s having agg_val %s %s" % (agg.groupfield, agg.cond_op, agg.condition)
            return self.qradarPrefixAgg, self.qradarSuffixAgg

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        qradarPrefix = "SELECT UTF8(payload) as search_payload from %s where " % (self.aql_database)
        if parsed.parsedAgg:
            (qradarPrefix, qradarSuffixAgg) = self.generateAggregation(parsed.parsedAgg)
            result = qradarPrefix + result
            result += qradarSuffixAgg
        else:
            result = qradarPrefix + result
        return result
