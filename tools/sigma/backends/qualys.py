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

import sigma
from .base import SingleTextQueryBackend
from .exceptions import PartialMatchError, FullMatchError
        
class QualysBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qualys saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qualys"
    active = True
    config_required = False
    default_config = ["sysmon", "qualys"]
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "%s is null"
    notNullExpression = "not (%s is null)"
    mapExpression = "%s:`%s`"
    mapListsSpecialHandling = True
    PartialMatchFlag = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fl = []
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type == list:
                fl.extend(item.target)
            else:
                fl.append(item.target)
        self.allowedFieldsList = list(set(fl))

    def generateORNode(self, node):
        new_list = []
        for val in node:
            if type(val) == tuple and not(val[0] in self.allowedFieldsList):
                pass
                # self.PartialMatchFlag = True
            else:
                new_list.append(val)

        generated = [self.generateNode(val) for val in new_list]
        filtered = [g for g in generated if g is not None]
        return self.orToken.join(filtered)

    def generateANDNode(self, node):
        new_list = []
        for val in node:
            if type(val) == tuple and not(val[0] in self.allowedFieldsList):
                self.PartialMatchFlag = True
            else:
                new_list.append(val)
        generated = [self.generateNode(val) for val in new_list]
        filtered = [g for g in generated if g is not None]
        return self.andToken.join(filtered)

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if key in self.allowedFieldsList:
                return self.mapExpression % (key, self.generateNode(value))
            else:
                return self.generateNode(value)
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = []
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s:`%s`' % (key, self.generateValueNode(item)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + (" or ".join(itemslist)) + ")"

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        all_keys = set()

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            if query == "()":
                self.PartialMatchFlag = None

            if self.PartialMatchFlag == True:
                raise PartialMatchError(query)
            elif self.PartialMatchFlag == None:
                raise FullMatchError(query)
            else:
                return query
