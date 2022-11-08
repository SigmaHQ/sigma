# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Roey

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

from sigma.parser.modifiers.type import SigmaRegularExpressionModifier

from sigma.parser.condition import SigmaAggregationParser
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin

class HumioBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Humio query. Contributed by SOC Prime. https://socprime.com"""
    identifier = "humio"
    active = True

    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " "
    orToken = " or "
    notToken = "!"
    subExpression = "%s"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "\"%s\""
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s=%s"
    regexExpression = "regex(\"%s=(\\\"%s\\\")\")"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: "/%s/"
    }

    def generateMapItemNode(self, node):
        key, value = node
        if isinstance(value, SigmaRegularExpressionModifier):# or isinstance(value, str) and "*" in value :
            return self.regexExpression % (key, self.cleanValue(value))
        else:
            return super().generateMapItemNode(node)

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return "%s(%s)" % (self.notToken, generated)
        else:
            return None

    def generateANDNode(self, node):
        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            if any([item for item in filtered if "regex" in item]):
                res = ""
                for item in filtered:
                    if item.startswith("regex"):
                        if res.endswith(" | "):
                            res = res.rstrip(" | ")
                        res += " | %s | " % item.strip(" | ")
                    else:
                        res += item
                return res.strip(" | ")
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [self.generateNode(val) for val in node]
        filtered = [g.strip(" | ") for g in generated if g is not None]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            if any([item for item in filtered if "regex" in item]):
                res = ""
                for item in filtered:
                    if item.startswith("regex"):
                        if res.endswith(" | "):
                            res = res.rstrip(" | ")
                        res += " | %s | " % item.strip(" | ")
                    else:
                        res += item
                return res.strip(" | ")
            return self.orToken.join(filtered)
        else:
            return None

    def cleanValue(self, val):
        if isinstance(val, SigmaRegularExpressionModifier):
            val = val.value
            if "\\" in val:
                val = re.sub(r"\\", r"\\\\\\", val)
        # if (val.startswith("*") or val.endswith("*")) and "\\" in val:
        #     val = re.sub(r"\\", r"\\\\\\", val)
        return super().cleanValue(val)

    def generateMapItemListNode(self, key, value):
        if isinstance(value, SigmaRegularExpressionModifier):
            key_mapped = self.fieldNameMapping(key, value)
            return {'regexp': {key_mapped: str(value)}}
        # if any([item for item in value if "*" in item]):
        #     return (" | " + " | ".join([self.regexExpression % (key, self.cleanValue(item)) for item in value]) + " | ")
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return " or ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])

    def generateAggregation(self, agg):
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield is None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield is None :
                    return " | val := count() | val %s %s" % (agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | count(field=%s, distinct=true, as=val) | val %s %s" % (agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield is None :
                    return " | val := count(field=%s) | val %s %s" % (agg.groupfield or "", agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | groupby(field=%s, function=count(field=%s, distinct=true, as=val)) | val %s %s" % (agg.groupfield or "", agg.aggfield or "", agg.cond_op, agg.condition)

        
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            #before = self.generateBefore(parsed)
            #after = self.generateAfter(parsed)

            result = ""
            # if before is not None:
            #     result = before
            if query is not None:
                result += query
            # if after is not None:
            #     result += after
            if result.endswith(" | "):
                result = result.strip(" | ")
            return result
