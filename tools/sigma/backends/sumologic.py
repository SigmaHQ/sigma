# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, juju4

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
from sigma.parser.condition import ConditionOR
from .base import SingleTextQueryBackend

# Sumo specifics
# https://help.sumologic.com/05Search/Search-Query-Language
# want _index or _sourceCategory for performance
# try to get most string match on first line for performance
# further sorting can be done with extra parsing
# No regex match, must use 'parse regex' https://help.sumologic.com/05Search/Search-Query-Language/01-Parse-Operators/02-Parse-Variable-Patterns-Using-Regex
# For some strings like Windows ProcessCmdline or LogonProcess, it might be good to force case lower and upper as Windows is inconsistent in logs

class SumoLogicBackend(SingleTextQueryBackend):
    """Converts Sigma rule into SumoLogic query"""
    identifier = "sumologic"
    active = True

    index_field = "_index"
    #reEscape = re.compile('("|\\\\(?![*?]))')
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
            # WIP
            # ex:
            # (QUERY) | timeslice 5m
            # | count_distinct(process) _timeslice,hostname
            # | where _count_distinct > 5
            #return " | timeslice %s | count_distinct(%s) %s | where _count_distinct > 0" % (self.interval, agg.aggfunc_notrans or "", agg.aggfield or "", agg.groupfield or "")
            #return " | timeslice %s | count_distinct(%s) %s | where _count_distinct %s %s" % (self.interval, agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)
        if agg.groupfield == None:
            #return " | %s(%s) | when _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
            return " | %s %s | where _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            return " | %s %s by %s | where _count %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)

    def generateBefore(self, parsed):
        # not required but makes query faster, especially if no FER or _index/_sourceCategory
        if self.logname:
            return "%s " % self.logname
        if self.service:
            return "%s %s " % (self.product, self.service)
        return ""

    def generate(self, sigmaparser):
        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']   # OS or Software
            self.service = sigmaparser.parsedyaml['logsource']['service']   # Channel
        except KeyError:
            self.product = None
            self.service = None

        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

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

            # adding parenthesis here in case 2 rules are aggregated together - ex: win_possible_applocker_bypass
            return "(" + result + ")"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO/FIXME! depending on deployment configuration, existing FER must be populate here (or backend config?)
        #aFL = ["EventID"]
        aFL = ["EventID", "sourcename", "CommandLine", "NewProcessName", "Image", "ParentImage", "ParentCommandLine", "ParentProcessName"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    #def generateCleanValueNodeLogsource(self, value):
    #    return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    # Sumologic: only removing '*' (in quotes, is litteral. without, is wildcard) and '"'
    def CleanNode(self, node):
        search_ptrn = re.compile(r"[\/@?#&%*\(\)\"]")
        replace_ptrn = re.compile(r"[\/@?#&%*\(\)\"]")
        match = search_ptrn.search(str(node))
        new_node = list()
        if match:
            replaced_str = replace_ptrn.sub('*', node)
            node = [x for x in replaced_str.split('*') if x]
            new_node.extend(node)
        else:
            new_node.append(node)
        node = new_node
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                if key in ("LogName","source"):
                    self.logname = value
                return self.mapExpression % (key, value)
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                if type(value) is str:
                    new_value = list()
                    value = self.CleanNode(value)
                    if type(value) == list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value)==1:
                        return "(" + self.generateANDNode(new_value) + ")"
                    else:
                        return "(" + self.generateORNode(new_value) + ")"
                else:
                    return self.generateValueNode(value)
            elif type(value) is list:
                new_value = list()
                for item in value:
                    item = self.CleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append(self.valueExpression % item[0])
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # from mixins.py
    #FIXME! input in simple quotes are not passing through this function. ex: rules/windows/sysmon/sysmon_vul_java_remote_debugging.yml, rules/apt/apt_sofacy_zebrocy.yml
    #   => OK only if field entry with list, not string
    def cleanValue(self, val, key = ''):
        print("DEBUG cleanValue0: %s" % val)
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        if self.reClear:
            val = self.reClear.sub("", val)
        # in sumologic, if key, can use wildcard outside of double quotes. if inside, it's litteral
        if key:
            val = re.sub(r'(.+?)\*(.+?)', '\g<1>"*"\g<2>', val, 0)
            val = re.sub(r'^\*', '*"', val)
            val = re.sub(r'\*$', '"*', val)
            # if unbalanced wildcard?
            if val.startswith('*"') and not (val.endswith('"*') or val.endswith('"')):
                val = val + '"'
            if val.endswith('"*') and not (val.startswith('*"') or val.startswith('"')):
                val = '"' + val
            # double escape if end quote
            if val.endswith('\\"*') and not val.endswith('\\\\"*'):
                val = re.sub(r'\\"\*$', '\\\\\\"*', val)
        print("DEBUG cleanValue1: %s" % val)
        return val

    # for keywords values with space
    def generateValueNode(self, node, key = ''):
        if type(node) is int:
            return self.cleanValue(str(node), key)
        if 'AND' in node:
            return "(" + self.cleanValue(str(node), key) + ")"
        else:
            return self.cleanValue(str(node), key)

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item, key)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + " OR ".join(itemslist) + ")"

    # generateORNode algorithm for ArcSightBackend & SumoLogicBackend class.
    def generateORNode(self, node):
        if type(node) == ConditionOR and all(isinstance(item, str) for item in node):
            new_value = list()
            for value in node:
                value = self.CleanNode(value)
                if type(value) is list:
                    new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                else:
                    new_value.append(value)
            return "(" + self.orToken.join([self.generateNode(val) for val in new_value]) + ")"
        return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        TODO/FIXME!
        """
        return fieldname
