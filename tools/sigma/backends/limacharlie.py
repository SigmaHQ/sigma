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
from collections import namedtuple
from .base import BaseBackend
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier

# A few helper functions for cases where field mapping cannot be done
# as easily one by one, or can be done more efficiently.
def _windowsEventLogArtifactFieldName(fieldName):
    if 'EventID' == fieldName:
        return 'Event/System/EventID'
    return 'Event/EventData/%s' % (fieldName,)

def _windowsEventLogEDRFieldName(fieldName):
    if 'EventID' == fieldName:
        return 'event/EVENT/System/EventID'
    return 'event/EVENT/EventData/%s' % (fieldName,)

def _mapProcessCreationOperations(node):
    # Here we fix some common pitfalls found in rules
    # in a consistent fashion (already processed to D&R rule).

    # First fixup is looking for a specific path prefix
    # based on a specific drive letter. There are many cases
    # where the driver letter can change or where the early
    # boot process refers to it as "\Device\HarddiskVolume1\".
    if ("starts with" == node["op"] and
        "event/FILE_PATH" == node["path"] and
        node["value"].lower().startswith("c:\\")):
        node["op"] = "matches"
        node["re"] = "^(?:(?:.:)|(?:\\\\Device\\\\HarddiskVolume.))\\\\%s" % (re.escape(node["value"][3:]),)
        del(node["value"])

    return node

# We support many different log sources so we keep different mapping depending
# on the log source and category.
# The mapping key is product/category/service.
# The mapping value is tuple like:
# - top-level parameters
# - pre-condition is a D&R rule node filtering relevant events.
# - field mappings is a dict with a mapping or a callable to convert the field name.
#       Individual mapping values can also be callabled(fieldname, value) returning a new fieldname and value.
# - isAllStringValues is a bool indicating whether all values should be converted to string.
# - keywordField is the field name to alias for keywords if supported or None if not.
# - postOpMapper is a callback that can modify an operation once it has been generated.
SigmaLCConfig = namedtuple('SigmaLCConfig', [
    'topLevelParams',
    'preConditions',
    'fieldMappings',
    'isAllStringValues',
    'keywordField',
    'postOpMapper',
    'isCaseSensitive',
])
_allFieldMappings = {
    'edr': {
        "windows//": SigmaLCConfig(
            topLevelParams = {
                "event": "WEL",
            },
            preConditions = {
                "op": "is windows",
            },
            fieldMappings = _windowsEventLogEDRFieldName,
            isAllStringValues = True,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "windows_defender//": SigmaLCConfig(
            topLevelParams = {
                "event": "WEL",
            },
            preConditions = {
                "op": "is windows",
            },
            fieldMappings = _windowsEventLogEDRFieldName,
            isAllStringValues = True,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "windows/process_creation/": SigmaLCConfig(
            topLevelParams = {
                "events": [
                    "NEW_PROCESS",
                    "EXISTING_PROCESS",
                ]
            },
            preConditions = {
                "op": "is windows",
            },
            fieldMappings = {
                "CommandLine": "event/COMMAND_LINE",
                "Image": "event/FILE_PATH",
                "ParentImage": "event/PARENT/FILE_PATH",
                "ParentCommandLine": "event/PARENT/COMMAND_LINE",
                "User": "event/USER_NAME",
                "OriginalFileName": "event/ORIGINAL_FILE_NAME",
                # Custom field names coming from somewhere unknown.
                "NewProcessName": "event/FILE_PATH",
                "ProcessCommandLine": "event/COMMAND_LINE",
                # Another one-off command line.
                "Command": "event/COMMAND_LINE",
            },
            isAllStringValues = False,
            keywordField = "event/COMMAND_LINE",
            postOpMapper = _mapProcessCreationOperations,
            isCaseSensitive = []
        ),
        "dns//": SigmaLCConfig(
            topLevelParams = {
                "event": "DNS_REQUEST",
            },
            preConditions = None,
            fieldMappings = {
                "query": "event/DOMAIN_NAME",
            },
            isAllStringValues = False,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "linux//": SigmaLCConfig(
            topLevelParams = {
                "events": [
                    "NEW_PROCESS",
                    "EXISTING_PROCESS",
                ]
            },
            preConditions = {
                "op": "is linux",
            },
            fieldMappings = {
                "exe": "event/FILE_PATH",
                "type": None,
            },
            isAllStringValues = False,
            keywordField = 'event/COMMAND_LINE',
            postOpMapper = None,
            isCaseSensitive = ['event/FILE_PATH']
        ),
        "unix//": SigmaLCConfig(
            topLevelParams = {
                "events": [
                    "NEW_PROCESS",
                    "EXISTING_PROCESS",
                ]
            },
            preConditions = {
                "op": "is linux",
            },
            fieldMappings = {
                "exe": "event/FILE_PATH",
                "type": None,
            },
            isAllStringValues = False,
            keywordField = 'event/COMMAND_LINE',
            postOpMapper = None,
            isCaseSensitive = ['event/FILE_PATH']
        ),
        "netflow//": SigmaLCConfig(
            topLevelParams = {
                "event": "NETWORK_CONNECTIONS",
            },
            preConditions = None,
            fieldMappings = {
                "destination.port": "event/NETWORK_ACTIVITY/DESTINATION/PORT",
                "source.port": "event/NETWORK_ACTIVITY/SOURCE/PORT",
            },
            isAllStringValues = False,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "/proxy/": SigmaLCConfig(
            topLevelParams = {
                "event": "HTTP_REQUEST",
            },
            preConditions = None,
            fieldMappings = {
                "c-uri|contains": "event/URL",
                "c-uri": "event/URL",
                "URL": "event/URL",
                "cs-uri-query": "event/URL",
                "cs-uri-stem": "event/URL",
            },
            isAllStringValues = False,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "macos/process_creation/": SigmaLCConfig(
            topLevelParams = {
                "events": [
                    "NEW_PROCESS",
                    "EXISTING_PROCESS",
                ]
            },
            preConditions = {
                "op": "is mac",
            },
            fieldMappings = {
                "CommandLine": "event/COMMAND_LINE",
                "Commandline": "event/COMMAND_LINE",
                "Image": "event/FILE_PATH",
                "ParentImage": "event/PARENT/FILE_PATH",
                "ParentCommandLine": "event/PARENT/COMMAND_LINE",
                "User": "event/USER_NAME",
                "OriginalFileName": "event/ORIGINAL_FILE_NAME",
                # Custom field names coming from somewhere unknown.
                "NewProcessName": "event/FILE_PATH",
                "ProcessCommandLine": "event/COMMAND_LINE",
                # Another one-off command line.
                "Command": "event/COMMAND_LINE",
            },
            isAllStringValues = False,
            keywordField = "event/COMMAND_LINE",
            postOpMapper = _mapProcessCreationOperations,
            isCaseSensitive = ['event/FILE_PATH']
        ),
    },
    "artifact": {
        "windows//": SigmaLCConfig(
            topLevelParams = {
                "target": "log",
                "log type": "wel",
            },
            preConditions = None,
            fieldMappings = _windowsEventLogArtifactFieldName,
            isAllStringValues = True,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
        "windows_defender//": SigmaLCConfig(
            topLevelParams = {
                "target": "log",
                "log type": "wel",
            },
            preConditions = None,
            fieldMappings = _windowsEventLogArtifactFieldName,
            isAllStringValues = True,
            keywordField = None,
            postOpMapper = None,
            isCaseSensitive = []
        ),
    }
}

class LimaCharlieBackend(BaseBackend):
    """Converts Sigma rule into LimaCharlie D&R rules. Contributed by LimaCharlie. https://limacharlie.io"""
    identifier = "limacharlie"
    active = True
    config_required = False
    default_config = ["limacharlie"]

    options = (
        (
            "lc_target",
            "edr",
            "Generate LimaCharlie D&R rules for the following target, one of: edr, artifact.",
            None,
        ),
    )

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

        # If there is a timeframe component, we do not currently
        # support it for now.
        if ruleConfig.get( 'detection', {} ).get( 'timeframe', None ) is not None:
            raise NotImplementedError("Timeframes are not supported by backend.")

        # Don't use service for now, most Windows Event Logs
        # uses a different service with no category, since we
        # treat all Windows Event Logs together we can ignore
        # the service.
        service = ""

        # See if we have a definition for the source combination.
        mappingKey = "%s/%s/%s" % (product, category, service)
        topFilter, preCond, mappings, isAllStringValues, keywordField, postOpMapper, isCaseSensitive = _allFieldMappings.get(self.lc_target, {}).get(mappingKey, tuple([None, None, None, None, None, None, None]))
        if mappings is None:
            raise NotImplementedError("Log source %s/%s/%s not supported by backend." % (product, category, service))

        # Field name conversions.
        self._fieldMappingInEffect = mappings

        # LC event type pre-selector for the type of data.
        self._preCondition = preCond

        # Are all the values treated as strings?
        self._isAllStringValues = isAllStringValues

        # Are we supporting keywords full text search?
        self._keywordField = keywordField

        # Call to fixup all operations after the fact.
        self._postOpMapper = postOpMapper

        # Event paths that are case sensitive.
        self._isCaseSensitiveFS = isCaseSensitive

        # Call the original generation code.
        detectComponent = super().generate(sigmaparser)

        # We expect a string (yaml) as output, so if
        # we get anything else we assume it's a core
        # library value and just return it as-is.
        if not isinstance( detectComponent, str):
            return detectComponent

        # This redundant to deserialize it right after
        # generating the yaml, but we try to use the parent
        # official class code as much as possible for future
        # compatibility.
        detectComponent = yaml.safe_load(detectComponent)

        # Check that we got a proper node and not just a string
        # which we don't really know what to do with.
        if not isinstance(detectComponent, dict):
            raise NotImplementedError("Selection combination not supported.")

        # Apply top level filter.
        detectComponent.update(topFilter)

        # Now prepare the Response component.
        respondComponents = [{
            "action": "report",
            "name": ruleConfig["title"],
        }]

        # Add a lot of the metadata available to the report.
        if ruleConfig.get("tags", None) is not None:
            respondComponents[0].setdefault("metadata", {})["tags"] = ruleConfig["tags"]

        if ruleConfig.get("description", None) is not None:
            respondComponents[0].setdefault("metadata", {})["description"] = ruleConfig["description"]

        if ruleConfig.get("references", None) is not None:
            respondComponents[0].setdefault("metadata", {})["references"] = ruleConfig["references"]

        if ruleConfig.get("level", None) is not None:
            respondComponents[0].setdefault("metadata", {})["level"] = ruleConfig["level"]

        if ruleConfig.get("author", None) is not None:
            respondComponents[0].setdefault("metadata", {})["author"] = ruleConfig["author"]

        if ruleConfig.get("falsepositives", None) is not None:
            respondComponents[0].setdefault("metadata", {})["falsepositives"] = ruleConfig["falsepositives"]

        # Assemble it all as a single, complete D&R rule.
        return yaml.safe_dump({
            "detect": detectComponent,
            "respond": respondComponents,
        }, default_flow_style = False)

    def generateQuery(self, parsed):
        # We override the generateQuery function because
        # we generate proper JSON structures internally
        # and only convert to string (yaml) once the
        # whole thing is assembled.
        result = self.generateNode(parsed.parsedSearch)

        if self._preCondition is not None:
            result = {
                "op": "and",
                "rules": [
                    self._preCondition,
                    result,
                ]
            }
            if self._postOpMapper is not None:
                result = self._postOpMapper(result)
        return yaml.safe_dump(result)

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if not filtered:
            return None

        # Map any possible keywords.
        filtered = self._mapKeywordVals(filtered)

        if 1 == len(filtered):
            if self._postOpMapper is not None:
                filtered[0] = self._postOpMapper(filtered[0])
            return filtered[0]
        result = {
            "op": "and",
            "rules": filtered,
        }
        if self._postOpMapper is not None:
            result = self._postOpMapper(result)
        return result

    def generateORNode(self, node):
        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if not filtered:
            return None

        # Map any possible keywords.
        filtered = self._mapKeywordVals(filtered)

        if 1 == len(filtered):
            if self._postOpMapper is not None:
                filtered[0] = self._postOpMapper(filtered[0])
            return filtered[0]
        result = {
            "op": "or",
            "rules": filtered,
        }
        if self._postOpMapper is not None:
            result = self._postOpMapper(result)
        return result

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is None:
            return None
        if not isinstance(generated, dict):
            raise NotImplementedError("Not operator not available on non-dict nodes.")
        generated["not"] = not generated.get("not", False)
        return generated

    def generateSubexpressionNode(self, node):
        return self.generateNode(node.items)

    def generateListNode(self, node):
        return [self.generateNode(value) for value in node]

    def generateMapItemNode(self, node):
        fieldname, value = node

        fieldNameAndValCallback = None

        # The mapping can be a dictionary of mapping or a callable
        # to get the correct value.
        if callable(self._fieldMappingInEffect):
            fieldname = self._fieldMappingInEffect(fieldname)
        else:
            try:
                # The mapping can also be a callable that will
                # return a mapped key AND value.
                if callable(self._fieldMappingInEffect[fieldname]):
                    fieldNameAndValCallback = self._fieldMappingInEffect[fieldname]
                else:
                    fieldname = self._fieldMappingInEffect[fieldname]
            except:
                raise NotImplementedError("Field name %s not supported by backend." % (fieldname,))

        # If fieldname returned is None, it's a special case where we
        # ignore the node.
        if fieldname is None:
            return None

        if isinstance(value, (int, str)):
            if fieldNameAndValCallback is not None:
                fieldname, value = fieldNameAndValCallback(fieldname, value)
            op, newVal = self._valuePatternToLcOp(value)
            newOp = {
                "op": op,
                "path": fieldname,
                "case sensitive": fieldname in self._isCaseSensitiveFS,
            }
            if op == "matches":
                newOp["re"] = newVal
            else:
                newOp["value"] = newVal
            if self._postOpMapper is not None:
                newOp = self._postOpMapper(newOp)
            return newOp
        elif isinstance(value, list):
            subOps = []
            for v in value:
                if fieldNameAndValCallback is not None:
                    fieldname, v = fieldNameAndValCallback(fieldname, v)
                op, newVal = self._valuePatternToLcOp(v)
                newOp = {
                    "op": op,
                    "path": fieldname,
                    "case sensitive": fieldname in self._isCaseSensitiveFS,
                }
                if op == "matches":
                    newOp["re"] = newVal
                else:
                    newOp["value"] = newVal
                if self._postOpMapper is not None:
                    newOp = self._postOpMapper(newOp)
                subOps.append(newOp)
            if 1 == len(subOps):
                return subOps[0]
            return {
                "op": "or",
                "rules": subOps
            }
        elif isinstance(value, SigmaTypeModifier):
            if isinstance(value, SigmaRegularExpressionModifier):
                if fieldNameAndValCallback is not None:
                    fieldname, value = fieldNameAndValCallback(fieldname, value)
                result = {
                    "op": "matches",
                    "path": fieldname,
                    "re": re.compile(value),
                }
                if self._postOpMapper is not None:
                    result = self._postOpMapper(result)
                return result
            else:
                raise TypeError("Backend does not support TypeModifier: %s" % (str(type(value))))
        elif value is None:
            if fieldNameAndValCallback is not None:
                fieldname, value = fieldNameAndValCallback(fieldname, value)
            result = {
                "op": "exists",
                "not": True,
                "path": fieldname,
            }
            if self._postOpMapper is not None:
                result = self._postOpMapper(result)
            return result
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateValueNode(self, node):
        return node

    def _valuePatternToLcOp(self, val):
        # Here we convert the string values supported by Sigma that
        # can include wildcards into either proper values (string or int)
        # or into altered values to be functionally equivalent using
        # a few different LC D&R rule operators.

        # No point evaluating non-strings.
        if not isinstance(val, str):
            return ("is", str(val) if self._isAllStringValues else val)

        # Is there any wildcard in this string? If not, we can short circuit.
        if "*" not in val and "?" not in val:
            return ("is", val)

        # Now we do a small optimization for the shortcut operators
        # available in LC. We try to see if the wildcards are around
        # the main value, but NOT within. If that's the case we can
        # use the "starts with", "ends with" or "contains" operators.
        isStartsWithWildcard = False
        isEndsWithWildcard = False
        tmpVal = val
        if tmpVal.startswith("*"):
            isStartsWithWildcard = True
            tmpVal = tmpVal[1:]
        if tmpVal.endswith("*") and not (tmpVal.endswith("\\*") and not tmpVal.endswith("\\\\*")):
            isEndsWithWildcard = True
            if tmpVal.endswith("\\\\*"):
                # An extra \ had to be there so it didn't escapte the
                # *, but since we plan on removing the *, we can also
                # remove one \.
                tmpVal = tmpVal[:-2]
            else:
                tmpVal = tmpVal[:-1]

        # Check to see if there are any other wildcards. If there are
        # we cannot use our shortcuts.
        if "*" not in tmpVal and "?" not in tmpVal:
            if isStartsWithWildcard and isEndsWithWildcard:
                return ("contains", tmpVal)

            if isStartsWithWildcard:
                return ("ends with", tmpVal)

            if isEndsWithWildcard:
                return ("starts with", tmpVal)

        # This is messy, but it is accurate in generating a RE based on
        # the simplified wildcard system, while also supporting the
        # escaping of those wildcards.
        segments = []
        tmpVal = val
        while True:
            nEscapes = 0
            for i in range(len(tmpVal)):
                # We keep a running count of backslash escape
                # characters we see so that if we meet a wildcard
                # we can tell whether the wildcard is escaped
                # (with odd number of escapes) or if it's just a
                # backslash literal before a wildcard (even number).
                if "\\" == tmpVal[i]:
                    nEscapes += 1
                    continue

                if "*" == tmpVal[i]:
                    if 0 == nEscapes:
                        segments.append(re.escape(tmpVal[:i]))
                        segments.append(".*")
                    elif nEscapes % 2 == 0:
                        segments.append(re.escape(tmpVal[:i - nEscapes]))
                        segments.append(tmpVal[i - nEscapes:i])
                        segments.append(".*")
                    else:
                        segments.append(re.escape(tmpVal[:i - nEscapes]))
                        segments.append(tmpVal[i - nEscapes:i + 1])
                    tmpVal = tmpVal[i + 1:]
                    break

                if "?" == tmpVal[i]:
                    if 0 == nEscapes:
                        segments.append(re.escape(tmpVal[:i]))
                        segments.append(".")
                    elif nEscapes % 2 == 0:
                        segments.append(re.escape(tmpVal[:i - nEscapes]))
                        segments.append(tmpVal[i - nEscapes:i])
                        segments.append(".")
                    else:
                        segments.append(re.escape(tmpVal[:i - nEscapes]))
                        segments.append(tmpVal[i - nEscapes:i + 1])
                    tmpVal = tmpVal[i + 1:]
                    break

                nEscapes = 0
            else:
                segments.append(re.escape(tmpVal))
                break

        val = ''.join(segments)

        return ("matches", val)

    def _mapKeywordVals(self, values):
        # This function ensures that the list of values passed
        # are proper D&R operations, if they are strings it indicates
        # they were requested as keyword matches. We only support
        # keyword matches when specified in the config. We generally just
        # map them to the most common field in LC that makes sense.
        mapped = []

        for val in values:
            # Non-keywords are just passed through.
            if not isinstance(val, str):
                mapped.append(val)
                continue

            if self._keywordField is None:
                raise NotImplementedError("Full-text keyboard searches not supported.")

            # This seems to be indicative only of "keywords" which are mostly
            # representative of full-text searches. We don't support that but
            # in some data sources we can alias them to an actual field.
            op, newVal = self._valuePatternToLcOp(val)
            newOp = {
                "op": op,
                "path": self._keywordField,
            }
            if op == "matches":
                newOp["re"] = newVal
            else:
                newOp["value"] = newVal
            mapped.append(newOp)

        return mapped
