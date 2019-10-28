# Output backends for sigmac
# Copyright 2019 Matthias Vallentin <matthias@tenzir.com>

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
import ipaddress
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier

from .base import SingleTextQueryBackend

def parse_vast_data(value):
    """Attempts to parse a value from a Sigma rule as a VAST data instance."""
    # Parsers that do not alter the original value
    identity_parsers = [
        ipaddress.ip_address,
        int
    ]
    for parser in identity_parsers:
        try:
            if parser(value) is not None:
                return value
        except ValueError:
            pass
    return None

class VASTQuerystringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into a VAST query string. Only searches, no aggregations."""
    identifier = "vast"
    active = True
    config_required = False
    reEscape = re.compile("([+\\-!(){}\\[\\]^\"~:/]|(?<!\\\\)\\\\(?![*?\\\\])|&&|\\|\\|)")
    reClear = None
    andToken = " && "
    orToken = " || "
    notToken = "! "
    subExpression = "(%s)"
    listExpression = "{%s}"
    listSeparator = ", "
    nullExpression = "%s == nil"
    notNullExpression = "%s != nil"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"
    valueExpression = "%s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: "/%s/"
    }

    # Cleaning a value means trying to parse it as VAST data value. If we
    # cannot parse the value successfully, we eventually consider the value as
    # a string.
    def cleanValue(self, value):
        result = parse_vast_data(value)
        if result is not None:
            return result
        return "\"%s\"" % value.replace("\'","\\\'")

    # We must override this method because a map expression for a pattern
    # differs from a normal equality lookup.
    def generateMapItemTypedNode(self, fieldname, value):
        predicate = self.mapExpression
        if type(value) is SigmaRegularExpressionModifier:
            predicate = "%s ~ %s"
        return predicate % (fieldname, self.generateTypedValueNode(value))
