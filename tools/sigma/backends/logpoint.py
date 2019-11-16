# Output backends for sigmac
# Copyright 2016-2017 Thomas Patzke, Ben de Haan

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

class LogPointBackend(SingleTextQueryBackend):
    """Converts Sigma rule into LogPoint query"""
    identifier = "logpoint"
    active = True
    config_required = False
    default_config = ["sysmon", "logpoint-windows"]

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = " -"
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "-%s=*"
    notNullExpression = "%s=*"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | chart %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            return " | chart %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)
