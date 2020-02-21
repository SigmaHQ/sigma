# Output backends for sigmac
# Copyright 2019 Jayden Zheng

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

class SQLBackend(SingleTextQueryBackend):
    """Converts Sigma rule into SQL query"""
    identifier = "sql"
    active = True

    andToken = " AND "                      # Token used for linking expressions with logical AND
    orToken = " OR "                        # Same for OR
    notToken = "NOT "                       # Same for NOT
    subExpression = "(%s)"                  # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = "(%s)"                 # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = ", "                    # Character for separation of list items
    valueExpression = "\"%s\""              # Expression of values, %s represents value
    nullExpression = "-%s=*"                # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = "%s=*"              # Expression of queries for not null values. %s is field name
    mapExpression = "%s = %s"               # Syntax for field/value conditions. First %s is fieldname, second is value
    mapMulti = "%s IN %s"                   # Syntax for field/value conditions. First %s is fieldname, second is value
    mapWildcard = "%s LIKE %s"              # Syntax for swapping wildcard conditions.
    mapSource = "%s=%s"                     # Syntax for sourcetype
    mapListsSpecialHandling = False         # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = "%s OR %s"     # Syntax for field/value condititons where map value is a list
    mapLength = "(%s %s)"

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return self.notToken + generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        fieldname, value = node
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if "," in self.generateNode(value) and "%" not in self.generateNode(value):
            return self.mapMulti % (transformed_fieldname, self.generateNode(value))
        elif "LENGTH" in transformed_fieldname:
            return self.mapLength % (transformed_fieldname, value)
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if "%" in self.generateNode(value):
                return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
            else:
                return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif "sourcetype" in transformed_fieldname:
            return self.mapSource % (transformed_fieldname, self.generateNode(value))
        elif "*" in str(value):
            return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return "(" + (" OR ".join(['%s LIKE %s' % (key, self.generateValueNode(item)) for item in value])) + ")"
    
    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        """
        return fieldname

    def cleanValue(self, val):
        if "*" == val:
            pass
        elif "*.*.*" in val:
            val = val.replace("*.*.*", "%")
        elif re.search(r'\*', val):
            val = re.sub(r'\*', '%', val)
        return val
