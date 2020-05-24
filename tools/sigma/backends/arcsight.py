# ArcSight backend for sigmac created by SOC Prime
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
from sigma.parser.condition import ConditionOR
from .base import SingleTextQueryBackend

class ArcSightBackend(SingleTextQueryBackend):
    """Converts Sigma rule into ArcSight saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "arcsight"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = " NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "\"%s\""
    containsExpression = "%s CONTAINS %s"
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s = %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s = %s"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        aFL = ["deviceVendor", "categoryDeviceGroup", "deviceProduct"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    def generateCleanValueNodeLogsource(self, value):
        return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    def CleanNode(self, node):
        search_ptrn = re.compile(r"[\/\\@?#&_%*',\(\)\" ]")
        replace_ptrn = re.compile(r"[ \/\\@?#&_%*',\(\)\" ]")
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
                return self.mapExpression % (key, self.generateCleanValueNodeLogsource(value))
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
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # for keywords values with space
    def generateValueNode(self, node):
        if type(node) is int:
            return self.cleanValue(str(node))
        if 'AND' in node:
            return "(" + self.cleanValue(str(node)) + ")"
        else:
            return self.cleanValue(str(node))

    # collect elements of Arcsight search using OR
    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return " OR ".join(itemslist)

    # prepare of tail for every translate
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        const_title = ' AND type != 2 | rex field = flexString1 mode=sed "s//Sigma: {}/g"'
        for parsed in sigmaparser.condparsed:
            return self.generateQuery(parsed) + const_title.format(sigmaparser.parsedyaml["title"])

    # Add "( )" for values
    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

    # generateORNode algorithm for ArcSightBackend class.
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

class ArcSightESMBackend(SingleTextQueryBackend):
    """Converts Sigma rule into ArcSight ESM saved search. Contributed by SOC Prime. https://socprime.com"""
    reEscape = re.compile('(["\\\()])')
    identifier = "arcsight-esm"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = " NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = '"%s"'
    containsExpression = "%s CONTAINS %s"
    startsWithExpression = "%s CONTAINS %s"
    endsWithExpression = "%s CONTAINS %s"
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s = %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s = %s"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        aFL = ["deviceVendor", "categoryDeviceGroup", "deviceProduct"]
        self.default_field = "deviceCustomString1"
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    def generateCleanValueNodeLogsource(self, value):
        return self.valueExpression % (self.cleanValue(str(value)))

    def CleanNode(self, node):
        if isinstance(node, str) and "*" in node and not node.startswith("*") and not node.endswith("*"):
            node = ["*{}*".format(x) for x in node.split('*') if x]
        return node

    #Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        value = self.CleanNode(value)
        if key in self.allowedFieldsList:
            if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                if isinstance(value, str) and value.startswith("*") and value.endswith("*"):
                    return self.containsExpression % (
                    key, self.generateCleanValueNodeLogsource(value))
                elif isinstance(value, str) and value.startswith("*"):
                    return self.endsWithExpression % (key, self.generateCleanValueNodeLogsource(value))
                elif isinstance(value, str) and value.endswith("*"):
                    return self.startsWithExpression % (key, self.generateCleanValueNodeLogsource(value))
                else:
                    return self.mapExpression % (key, self.generateCleanValueNodeLogsource(value))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            key = self.default_field
            if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):

                if isinstance(value, str) and value.startswith("*") and value.endswith("*"):
                    return self.containsExpression % (key, self.generateValueNode(self.CleanNode(value)))
                elif isinstance(value, str) and value.startswith("*"):
                    return self.endsWithExpression % (key, self.generateValueNode(self.CleanNode(value)))
                elif isinstance(value, str) and value.endswith("*"):
                    return self.startsWithExpression % (key, self.generateValueNode(self.CleanNode(value)))
                else:
                    return self.mapExpression % (key, self.generateValueNode(value))
            elif isinstance(value, list):
                new_value = list()
                for item in value:
                    item = self.CleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append( self.containsExpression % (key, item[0]))
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in item]))
                    else:
                        if isinstance(item, str) and (item.startswith("*") or item.endswith("*")):
                            new_value.append(self.containsExpression % (key, self.generateValueNode(self.cleanValue(item))))
                        else:
                            new_value.append(self.mapExpression %(key, self.cleanValue(item)))
                return self.generateORNode(new_value)
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # for keywords values with space
    def generateValueNode(self, node):
        if type(node) is int:
            return self.cleanValue(str(node))
        if 'AND' in node:
            return "(" + self.cleanValue(str(node)) + ")"
        else:
            return self.valueExpression % (self.cleanValue(str(node)))

    # collect elements of Arcsight search using OR
    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if isinstance(item, str) and (item.startswith("*") or item.endswith("*")):
                itemslist.append(self.containsExpression % (
                    key, self.generateValueNode(item)))
            else:
                itemslist.append(
                    '%s = %s' % (key, self.generateValueNode(item)))

        return " OR ".join(itemslist)

    # prepare of tail for every translate
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            return self.generateQuery(parsed)

    # Add "( )" for values
    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

    # generateORNode algorithm for ArcSightBackend class.
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
        elif isinstance(node, list) and all(isinstance(item, str) for item in node):
            return "(" + self.orToken.join([val for val in node]) + ")"
        else:
            return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"
