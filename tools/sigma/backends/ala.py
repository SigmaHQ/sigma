# Azure Log Analytics output backend for sigmac
# John Tuckner (@tuckner)

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
import xml.etree.ElementTree as xml
import os
from .base import SingleTextQueryBackend
from .exceptions import NotSupportedError

class AzureLogAnalyticsBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Azure Log Analytics Queries."""
    identifier = "ala"
    active = True

    reEscape = re.compile('("|\\\\(?![*?]))')
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isnull(%s)"
    notNullExpression = "isnotnull(%s)"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)

    def id_mapping(self, src):
        """Identity mapping, source == target field name"""
        if self.product == "sysmon":
            src = src + "_CF"
        return src

    def map_sysmon_schema(self, eventid):
        schema_keys = []
        abs_path = os.path.abspath(os.path.dirname(__file__))
        sysmon_schema = os.path.join(abs_path, "../../../contrib/sysmon-schema.xml")
        try:
            tree = xml.parse(sysmon_schema)
        except:
            raise NotSupportedError("Required Sysmon schema not provided")
        root = tree.getroot()
        for child in root.iter('event'):
            if child.attrib['value'] == str(eventid):
                for d in list(child):
                    schema_keys.append(d.attrib["name"])
        parse_arg = ''
        for schema_key in schema_keys:
            parse_arg += "'Data Name=\"{0}\">' {0} '<' * ".format(schema_key)
        return parse_arg

    def default_value_mapping(self, val):
        op = "=="
        if type(val) == str and "*" in val[1:-1]:     # value contains * inside string - use regex match
            op = "matches regex"
            val = re.sub('(\\\\(?![*?]))', '\\\\\\\\\\\\\g<1>', val)
            val = re.sub('([".^$])', '\\\\\\\\\g<1>', val)
            val = re.sub('\\*', '.*', val)
            val = re.sub('\\?', '.', val)
        elif type(val) == str:                           # value possibly only starts and/or ends with *, use prefix/postfix match
            if val.endswith("*") and val.startswith("*"):
                op = "contains"
                val = self.cleanValue(val[1:-1])
            elif val.endswith("*"):
                op = "startswith"
                val = self.cleanValue(val[:-1])
            elif val.startswith("*"):
                op = "endswith"
                val = self.cleanValue(val[1:])

        return "%s \"%s\"" % (op, val)

    def generate(self, sigmaparser):
        self.table = None
        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']
            self.service = sigmaparser.parsedyaml['logsource']['service']
        except KeyError:
            self.product = None
            self.service = None

        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.table is None:
            raise NotSupportedError("No table could be determined from Sigma rule")
        if self.table is "Event":
            parse_string = self.map_sysmon_schema(self.eventid) 
            before = "{0} | parse EventData with * {1} | where ".format(self.table, parse_string)
        else:
            before = "%s | where " % self.table
        return before 

    def generateMapItemNode(self, node):
        """
        ALA queries, like ATP, refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        if type(value) == list:         # handle map items with values list like multiple OR-chained conditions
            return self.generateORNode(
                    [(key, v) for v in value]
                    )
        elif key == "EventID":            # EventIDs are not reflected in condition but in table selection
            if self.service == "security":
                self.table = "SecurityEvent"
            if self.service == "sysmon":
                self.table = "Event"
                self.eventid = value
        elif type(value) in (str, int):     # default value processing
            mapping = (key, self.default_value_mapping)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, value)
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, value)]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(val))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        return super().generateMapItemNode(node)
