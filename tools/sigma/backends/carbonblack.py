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
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin

class SplunkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "carbonblack"
    active = True
    index_field = "index"

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " and "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "%s"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s:%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, key, value):
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val | search val %s %s" % (agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val by %s| search val %s %s" % (agg.groupfield, agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)

        
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        columns = list()

        for parsed in sigmaparser.condparsed:
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
            if mapped is not None:
                result += fields

            return result
    
