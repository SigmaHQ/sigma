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
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class QRadarBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qradar saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qradar"
    active = True
    config_required = False
    default_config = ["sysmon", "qradar"]
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
        if key == None:
            return ""
        if " " in key:
            key = "\"%s\"" % (key)
            return key
        else:
            return key

    def cleanValue(self, value):
        """Remove quotes in text"""
        return value.replace("\'","\\\'")

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        elif type(node) in (str, int):
            return self.generateValueNode(node, False)
        elif type(node) == list:
            return self.generateListNode(node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))


    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                return "%s ilike %s" % (self.cleanKey(key), self.generateValueNode(value, True))
            elif type(value) in (str, int):
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value, True))
            else:
                return self.mapExpression % (self.cleanKey(key), self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        elif value is None:
            return self.nullExpression % (key, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if item is None:
                itemslist.append(self.nullExpression % (key))
            elif type(item) == str and "ip" in key and ("/16" in item or "/24" in item):
                itemslist.append("INCIDR(%s, %s)" % (self.generateValueNode(item, True), self.cleanKey(key)))
            elif type(item) == str and "*" in item:
                item = item.replace("*", "%")
                itemslist.append('%s ilike %s' % (self.cleanKey(key), self.generateValueNode(item, True)))
            else:
                itemslist.append('%s = %s' % (self.cleanKey(key), self.generateValueNode(item, True)))
        return '('+" or ".join(itemslist)+')'

    def generateMapItemTypedNode(self, fieldname, value):
        if type(value) == SigmaRegularExpressionModifier:
            regex = str(value)
            # Regular Expressions have to match the full value in QRadar
            if not (regex.startswith('^') or regex.startswith('.*')):
                regex = '.*' + regex
            if not (regex.endswith('$') or regex.endswith('.*')):
                regex = regex + '.*'
            return "%s imatches %s" % (self.cleanKey(fieldname), self.generateValueNode(regex, True))
        else:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(value.identifier))

    def generateValueNode(self, node, keypresent):
        if keypresent == False:
            return "UTF8(payload) ilike \'{0}{1}{2}\'".format("%", self.cleanValue(str(node)), "%")
        else:
            return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def generateAggregation(self, agg, timeframe='00'):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            self.qradarPrefixAgg = "SELECT %s(%s) as agg_val from %s where" % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
            self.qradarSuffixAgg = " group by %s having agg_val %s %s" % (self.cleanKey(agg.aggfield), agg.cond_op, agg.condition)
            return self.qradarPrefixAgg, self.qradarSuffixAgg
        elif agg.groupfield != None and timeframe == '00':
                self.qradarPrefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
                self.qradarSuffixAgg = " group by %s having agg_val %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition)
                return self.qradarPrefixAgg, self.qradarSuffixAgg
        elif agg.groupfield != None and timeframe != None:
            for key, duration in self.generateTimeframe(timeframe).items():
                self.qradarPrefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
                self.qradarSuffixAgg = " group by %s having agg_val %s %s LAST %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition, duration, key)
                return self.qradarPrefixAgg, self.qradarSuffixAgg
        else:
            self.qradarPrefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
            self.qradarSuffixAgg = " group by %s having agg_val %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition)
            return self.qradarPrefixAgg, self.qradarSuffixAgg

    def generateTimeframe(self, timeframe):
        time_unit = timeframe[-1:]
        duration = timeframe[:-1]
        timeframe_object = {}
        if time_unit == "s":
            timeframe_object['seconds'] = int(duration)
        elif time_unit == "m":
            timeframe_object['minutes'] = int(duration)
        elif time_unit == "h":
            timeframe_object['hours'] = int(duration)
        elif time_unit == "d":
            timeframe_object['days'] = int(duration)
        else:
            timeframe_object['months'] = int(duration)
        return timeframe_object

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            return result

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        self.parsedlogsource = sigmaparser.get_logsource().index
        if any("flow" in i for i in self.parsedlogsource):
            aql_database = "flows"
        else:
            aql_database = "events"

        qradarPrefix="SELECT UTF8(payload) as search_payload"
        try:
            mappedFields = []
            for field in sigmaparser.parsedyaml["fields"]:
                    mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                    mappedFields.append(mapped)
                    if " " in mapped and not "(" in mapped:
                        qradarPrefix += ", \"" + mapped + "\""
                    else:
                        qradarPrefix +=  ", " + mapped

        except KeyError:    # no 'fields' attribute
            mapped = None
            pass
        qradarPrefix += " from %s where " % (aql_database)

        try:
            timeframe = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            timeframe = None

        if parsed.parsedAgg and timeframe == None:
            (qradarPrefix, qradarSuffixAgg) = self.generateAggregation(parsed.parsedAgg)
            result = qradarPrefix + result
            result += qradarSuffixAgg
        elif parsed.parsedAgg != None and timeframe != None:
            (qradarPrefix, qradarSuffixAgg) = self.generateAggregation(parsed.parsedAgg, timeframe)
            result = qradarPrefix + result
            result += qradarSuffixAgg
        else:
            result = qradarPrefix + result
        return result
