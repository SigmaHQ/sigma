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

from .base import SingleTextQueryBackend

class QRadarBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qradar saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qradar"
    active = True
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "\'%s\'"
    keyExpression = "\"%s\""
    nullExpression = "%s is null"
    notNullExpression = "not (%s is null)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    allKeys_aFL = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.allKeys_aFL = True
        aFL = ["deviceVendor", "categoryDeviceGroup", "deviceProduct"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type == list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))


    def generateANDNode(self, node):
        return '(' + self.andToken.join([self.generateNode(val) for val in node]) + ')'

    def generateORNode(self, node):
        return '('+self.orToken.join([self.generateNode(val) for val in node])+')'

    def generateNOTNode(self, node):
        return self.notToken + self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateSCValueNodeLogsource(self, value):
        if value == 'Microsoft':
            if self.allKeys_aFL == True:
                self.const_start = "*"
            return self.cleanValue(str(value))

        else:
            if self.allKeys_aFL == True:
                self.const_start = "*"
            return self.cleanValue(str(value))


    def generateMapItemNode(self, node):
        key, value = node

        if key in self.allowedFieldsList:
            if key == 'deviceProduct':
                return self.generateSCValueNodeLogsource(value)
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                return self.mapExpression % (self.keyExpression % key, self.valueExpression % self.generateSCValueNodeLogsource(value))
            elif type(value) == list:
                return self.generateMapItemListNode(key, value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        else:
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                if type(value) == str:
                    new_value = list()

                    if type(value) == list:
                        new_value.append(self.andToken.join([val for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value)==1:
                        return self.generateValueNode(value)
                    else:
                        return "(" + self.generateORNode(new_value) + ")"
                else:
                    return self.generateValueNode(value)
            elif type(value) == list:
                new_value = list()
                for item in value:
                    # item = self.CleanNode(item)
                    if type(item) == list and len(item) == 1:
                        new_value.append(self.valueExpression % item[0])
                    elif type(item) == list:
                        new_value.append(self.andToken.join([val for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (self.keyExpression % key, self.valueExpression % self.generateSCValueNodeLogsource(item)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return '('+" or ".join(itemslist)+')'

    def generateValueNode(self, node):
        if type(node) == str and "*" in node:
            self.node = node.replace("*", "%")
            return "{} '{}'".format("search_payload ilike", self.cleanValue(str(self.node)))
        return "{} '{}'".format("search_payload ilike", self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def generate(self, sigmaparser):
        self.const_start = "SELECT UTF8(payload) as search_payload from events where "
        for parsed in sigmaparser.condparsed:
            self.output.print(self.const_start + self.generateQuery(parsed))                
