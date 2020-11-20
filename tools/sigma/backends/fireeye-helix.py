# Output backends for sigmac
# Copyright 2020 FireEye, Inc.
# Author: Alek Rollyson <alek.rollyson@fireeye.com>

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

from sigma.backends.base import SingleTextQueryBackend

from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.transform import (
    SigmaContainsModifier,
    SigmaStartswithModifier,
    SigmaEndswithModifier,
)
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier


class FireEyeHelixBackend(SingleTextQueryBackend):
    """Converts Sigma rule into FireEye Helix Query Language."""

    identifier = "fireeye-helix"
    active = True
    index_field = "metaclass"
    nonTaxonomyField = "rawmsg"

    andToken = " "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "[%s]"
    listAndExpression = "&[%s]"
    listSeparator = ","
    valueExpression = "`%s`"
    nullExpression = "missing(%s)"
    notNullExpression = "has(%s)"
    mapExpression = "%s=%s"
    mapContainsExpression = "%s:%s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: "/%s/",
        SigmaContainsModifier: "%s",
        SigmaStartswithModifier: "%s",
        SigmaEndswithModifier: "%s",
    }
    containsMatchFields = [index_field, nonTaxonomyField]
    exactMatchFields = ["eventid", "srcport", "dstport", "channel"]

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        # Retrieve a list of fields explicity mapped in the config so we can use "rawmsg" for unmapped fields
        fl = ["metaclass", "channel"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type == list:
                fl.extend(item.target)
            else:
                fl.append(item.target)
        self.allowedFieldsList = list(set(fl))

    def generateMapItemNode(self, node):
        key, value = node
        # Default our expression to a contains match
        divinedExpression = self.mapContainsExpression
        # If a field defines what the expression would be, use this to lock it in despite what the value determines
        fieldForcedExpression = False
        # Special field handling
        if key not in self.allowedFieldsList:
            key = self.nonTaxonomyField
        if key in self.containsMatchFields:
            divinedExpression = self.mapContainsExpression
            fieldForcedExpression = True
        elif key in self.exactMatchFields:
            divinedExpression = self.mapExpression
            fieldForcedExpression = True

        # Always exact match integers
        if isinstance(value, int):
            if not fieldForcedExpression:
                divinedExpression = self.mapExpression
            return divinedExpression % (key, self.generateNode(value))
        elif isinstance(value, str):
            value, divinedExpression = self.parseStringValue(
                key, value, divinedExpression, fieldForcedExpression, False
            )
            return divinedExpression % (key, self.generateNode(value))
        elif isinstance(value, list):
            newList = []
            # Iterate over our list values to deal with wildcards in strings
            for _value in value:
                if isinstance(_value, str):
                    _value, divinedExpression = self.parseStringValue(
                        key, _value, divinedExpression, fieldForcedExpression, True
                    )
                    newList.append(_value)
                else:
                    newList.append(_value)
            return divinedExpression % (key, self.generateNode(newList))
        elif isinstance(value, SigmaTypeModifier):
            if isinstance(value, (SigmaStartswithModifier, SigmaEndswithModifier)):
                divinedExpression = self.mapContainsExpression
                # Strip prefix/suffix matching wildcards on rawmsg field searches
                if key == self.nonTaxonomyField and isinstance(value, str):
                    value.strip("*")
            elif isinstance(value, SigmaContainsModifier):
                divinedExpression = self.mapContainsExpression
            elif isinstance(value, SigmaRegularExpressionModifier):
                divinedExpression = self.mapContainsExpression
            return divinedExpression % (key, self.generateTypedValueNode(value))
        elif value is None:
            return self.nullExpression % (key,)
        else:
            raise TypeError(
                "Backend does not support map values of type " + str(type(value))
            )

    def generateNULLValueNode(self, node):
        # Don't generate null value nodes for fields we don't map
        if node.item is "rawmsg":
            return None
        else:
            return self.notNullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        # Don't generate not null value nodes for fields we don't map
        if node.item is "rawmsg":
            return None
        else:
            return self.nullExpression % (node.item)

    def parseStringValue(
        self, key, value, divinedExpression, fieldForcedExpression, isList
    ):
        # Raise a NotImplementedError if the query contains mid value wildcards for now
        # TODO figure out how to best handle this
        if "*" in value[1:-1]:
            raise NotImplementedError(
                "Backend does not support queries containing mid value wildcards."
            )
        # Strip balanced wildcards
        if value.startswith("*") and value.endswith("*"):
            value = value[1:-1]
            if not fieldForcedExpression:
                divinedExpression = self.mapContainsExpression
        # Prefix/suffix matches are "contains" operators
        elif value.startswith("*") or value.endswith("*"):
            # Strip wildcards from rawmsg matching because we don't know where in the log we're matching from
            if key == self.nonTaxonomyField:
                value = value.strip("*")
            if not fieldForcedExpression:
                divinedExpression = self.mapContainsExpression
        # If we have no indicators of this being a "contains" match for a string, use an exact match
        else:
            if not fieldForcedExpression and not isList:
                divinedExpression = self.mapExpression

        return value, divinedExpression
