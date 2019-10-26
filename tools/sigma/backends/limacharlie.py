# LimaCharlie backend for sigmac created by LimaCharlie.io
# Copyright 2019 Refraction Point, Inc

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
import yaml
from .base import BaseBackend
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier

# We support many different log sources so we keep different mapping depending
# on the log source and category.
# Top level is product.
# Second level is category.
# Thirs level is service.
# Fourth level is a tuple (pre-condition, field mappings).
_allFieldMappings = {
    "windows/process_creation/": ({
        "op": "is windows",
        "events": [
            "NEW_PROCESS",
            "EXISTING_PROCESS",
        ]
    }, {
        "CommandLine": "event/COMMAND_LINE",
        "Image": "event/FILE_PATH",
        "ParentImage": "event/PARENT/FILE_PATH",
        "ParentCommandLine": "event/PARENT/COMMAND_LINE",
    }),
}

class LimaCharlieBackend(BaseBackend):
    """Converts Sigma rule into LimaCharlie D&R rules. Contributed by LimaCharlie. https://limacharlie.io"""
    identifier = "limacharlie"
    active = True

    def generate(self, sigmaparser):
        # Take the log source information and figure out which set of mappings to use.
        ls_rule = sigmaparser.parsedyaml['logsource']
        try:
            category = ls_rule['category']
        except KeyError:
            category = None
        try:
            product = ls_rule['product']
        except KeyError:
            product = None
        try:
            service = ls_rule['service']
        except KeyError:
            service = ""

        mappingKey = "%s/%s/%s" % (product, category, service)
        preCond, mappings = _allFieldMappings.get(mappingKey, tuple([None, None]))
        if mappings is None:
            raise NotImplementedError("Log source %s/%s not supported by backend." % (product, category))

        self._fieldMappingInEffect = mappings
        self._preCondition = preCond

        return super().generate(sigmaparser)

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if self._preCondition is not None:
            result = {
                "op": "and",
                "rules": [
                    self._preCondition,
                    result,
                ]
            }
        return yaml.safe_dump(result)

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return {
                "op": "and",
                "rules": filtered,
            }
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return {
                "op": "or",
                "rules": filtered,
            }
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            generated[ 'not' ] = True
            return generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return generated
        else:
            return None

    def generateListNode(self, node):
        return [self.generateNode(value) for value in node]

    def generateMapItemNode(self, node):
        fieldname, value = node

        fieldname = self._fieldMappingInEffect.get(fieldname, None)
        if fieldname is None:
            raise NotImplementedError("Field name %s not supported by backend." % (fieldname,))

        if isinstance(value, (int, str)):
            op, newVal = self._valuePatternToLcOp(value)
            return {
                "op": op,
                "path": fieldname,
                "value": newVal,
            }
        elif isinstance(value, list):
            subOps = []
            for v in value:
                op, newVal = self._valuePatternToLcOp(v)
                subOps.append({
                    "op": op,
                    "path": fieldname,
                    "value": newVal,
                })
            if 1 == len(subOps):
                return subOps[0]
            return {
                "op": "or",
                "rules": subOps
            }
        elif isinstance(value, SigmaTypeModifier):
            if isinstance(value, SigmaRegularExpressionModifier):
                return {
                    "op": "matches",
                    "path": fieldname,
                    "re": re.compile(value),
                }
            else:
                raise TypeError("Backend does not support TypeModifier: %s" % (str(type(value))))
        elif value is None:
            return {
                "op": "exists",
                "not": True,
                "path": fieldname,
            }
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateValueNode(self, node):
        return node

    def generateNULLValueNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            generated[ "op" ] = "exists"
            generated[ "not" ] = True
            return generated
        else:
            return None

    def generateNotNULLValueNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            generated[ "op" ] = "exists"
            generated[ "not" ] = False
            return generated
        else:
            return None

    def _valuePatternToLcOp(self, val):
        if not isinstance(val, str):
            return ("is", val)
        # The following logic is taken from the WDATP backend to translate
        # the basic wildcard format into proper regular expression.
        if "*" in val[1:-1]:
            # Contains a wildcard within, must be translated.
            # TODO: getting a W605 from the \g escape, this may be broken.
            val = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', val)
            val = re.sub('\\*', '.*', val)
            val = re.sub('\\?', '.', val)
            return ("matches", val)
        # value possibly only starts and/or ends with *, use prefix/postfix match
        # TODO: this is actually not correct since the string could end with
        # a \* expression which would mean it's NOT a wildcard. We'll gloss over
        # it for now to get something out but it should eventually be fixed
        # so that it's accurate in all corner cases.
        if val.endswith("*") and val.startswith("*"):
            return ("contains", val[1:-1])
        elif val.endswith("*"):
            return ("starts with", val[:-1])
        elif val.startswith("*"):
            return ("ends with", val[1:])
        return ("is", val)