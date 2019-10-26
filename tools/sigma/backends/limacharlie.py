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

# A few helper functions for cases where field mapping cannot be done
# as easily one by one, or can be done more efficiently.
def _windowsEventLogFieldName(fieldName):
    if 'EventID' == fieldName:
        return 'Event/System/EventID'
    return 'Event/EventData/%s' % (fieldName,)

# We support many different log sources so we keep different mapping depending
# on the log source and category.
# The mapping key is product/category/service.
# The mapping value is (pre-condition, field mappings, isAllStringValues).
# - pre-condition is a D&R rule node filtering relevant events.
# - field mappings is a dict with a mapping or a callable to convert the field name.
# - isAllStringValues is a bool indicating whether all values should be converted to string.
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
        "User": "event/USER_NAME",
        # This field is redundant in LC, it seems to always be used with Image
        # so we will ignore it.
        "OriginalFileName": None,
        # Custom field names coming from somewhere unknown.
        "NewProcessName": "event/FILE_PATH",
        "ProcessCommandLine": "event/COMMAND_LINE",
    }, False),
    "windows//": ({
        "target": "log",
        "log type": "wel",
    }, _windowsEventLogFieldName, True),
    "windows_defender//": ({
        "target": "log",
        "log type": "wel",
    }, _windowsEventLogFieldName, True),
}

class LimaCharlieBackend(BaseBackend):
    """Converts Sigma rule into LimaCharlie D&R rules. Contributed by LimaCharlie. https://limacharlie.io"""
    identifier = "limacharlie"
    active = True

    def generate(self, sigmaparser):
        # Take the log source information and figure out which set of mappings to use.
        ruleConfig = sigmaparser.parsedyaml
        ls_rule = ruleConfig['logsource']
        try:
            category = ls_rule['category']
        except KeyError:
            category = ""
        try:
            product = ls_rule['product']
        except KeyError:
            product = ""
        # try:
        #     service = ls_rule['service']
        # except KeyError:
        #     service = ""
        # Don't use service for now, most Windows Event Logs
        # uses a different service with no category, since we
        # treat all Windows Event Logs together we can ignore
        # the service.
        service = ""

        mappingKey = "%s/%s/%s" % (product, category, service)
        preCond, mappings, isAllStringValues = _allFieldMappings.get(mappingKey, tuple([None, None, None]))
        if mappings is None:
            raise NotImplementedError("Log source %s/%s/%s not supported by backend." % (product, category, service))

        self._fieldMappingInEffect = mappings
        self._preCondition = preCond
        self._isAllStringValues = isAllStringValues

        detectComponent = super().generate(sigmaparser)
        if not isinstance( detectComponent, str):
            return detectComponent

        # This redundant to deserialize it right after
        # generating the yaml, but we try to use the parent
        # official class code as much as possible for future
        # compatibility.
        detectComponent = yaml.safe_load(detectComponent)
        respondComponents = [{
            "action": "report",
            "name": ruleConfig["title"],
        }]

        if ruleConfig.get("tags", None) is not None:
            respondComponents[0].setdefault("metatdata", {})["tags"] = ruleConfig["tags"]

        if ruleConfig.get("description", None) is not None:
            respondComponents[0].setdefault("metatdata", {})["description"] = ruleConfig["description"]

        if ruleConfig.get("references", None) is not None:
            respondComponents[0].setdefault("metatdata", {})["references"] = ruleConfig["references"]

        if ruleConfig.get("level", None) is not None:
            respondComponents[0].setdefault("metatdata", {})["level"] = ruleConfig["level"]

        if ruleConfig.get("author", None) is not None:
            respondComponents[0].setdefault("metatdata", {})["author"] = ruleConfig["author"]

        return yaml.safe_dump({
            "detect": detectComponent,
            "respond": respondComponents,
        })

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
            if 1 == len(filtered):
                return filtered[0]
            return {
                "op": "and",
                "rules": filtered,
            }
        else:
            return None

    def generateORNode(self, node):
        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            if 1 == len(filtered):
                return filtered[0]
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

        # The mapping can be a dictionary of mapping or a callable
        # to get the correct value.
        if callable(self._fieldMappingInEffect):
            fieldname = self._fieldMappingInEffect(fieldname)
        else:
            try:
                fieldname = self._fieldMappingInEffect[fieldname]
            except:
                raise NotImplementedError("Field name %s not supported by backend." % (fieldname,))

        # If fieldname returned is None, it's a special case where we
        # ignore the node.
        if fieldname is None:
            return None

        if isinstance(value, (int, str)):
            op, newVal = self._valuePatternToLcOp(value)
            return {
                "op": op,
                "path": fieldname,
                "value": newVal,
                "case sensitive": False,
            }
        elif isinstance(value, list):
            subOps = []
            for v in value:
                op, newVal = self._valuePatternToLcOp(v)
                subOps.append({
                    "op": op,
                    "path": fieldname,
                    "value": newVal,
                    "case sensitive": False,
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
            return ("is", str(val) if self._isAllStringValues else val)
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