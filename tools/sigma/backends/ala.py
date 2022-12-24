# Azure Log Analytics output backend for sigmac
# John Tuckner (@tuckner)

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
import os
import sys
import re
import json
import xml.etree.ElementTree as xml

from datetime import timedelta
from uuid import uuid4

from sigma.config.mapping import (
    SimpleFieldMapping, MultiFieldMapping, ConditionalFieldMapping
)
from sigma.parser.condition import SigmaAggregationParser, SigmaConditionParser, SigmaConditionTokenizer

from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.backends.base import SingleTextQueryBackend

from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.transform import SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier
from .data import sysmon_schema
from .exceptions import NotSupportedError

class AzureLogAnalyticsBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Azure Log Analytics Queries."""
    identifier = "ala"
    active = True
    options = SingleTextQueryBackend.options + (
        ("sysmon", False, "Generate Sysmon event queries for generic rules", None),
        (
            "use_fields",
            False,
            "Use fields to generate project and aggregation clauses",
            None,
        ),
    )
    config_required = False

    reEscape = re.compile('(\\\|"|(?<!)(?![*?]))')
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isnull(%s)"
    notNullExpression = "isnotnull(%s)"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: "matches regex \"(?i)%s\"",
        SigmaContainsModifier: "contains \"%s\""
    }

    # _WIN_SECURITY_EVENT_MAP = {
    #     "Image": "NewProcessName",
    #     "ParentImage": "ParentProcessName",
    #     "User": "SubjectUserName",
    # }

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.category = None
        self.product = None
        self.service = None
        self.table = None
        self.eventid = None
        self.tableAggJoinFields = None
        self.tableAggTimeField = None
        self._parser = None
        self._fields = None
        self._agg_var = None
        self._has_logsource_event_cond = False
        if not self.sysmon and not self.sigmaconfig.config:
            self._field_map = {}#self._WIN_SECURITY_EVENT_MAP
        else:
            self._field_map = {}

    def map_sysmon_schema(self, eventid):
        schema_keys = []
        try:
            tree = xml.ElementTree(xml.fromstring(sysmon_schema))
        except:
            raise NotSupportedError("Required Sysmon schema not provided")
        root = tree.getroot()
        for child in root.iter('event'):
            if child.attrib['value'] == str(eventid):
                for d in list(child):
                    schema_keys.append(d.attrib["name"])
        parse_arg = ''
        for schema_key in schema_keys:
            parse_arg += "'Data Name=\"{0}\">' {0} '<' * ".format(schema_key)
        return parse_arg

    def default_value_mapping(self, val):
        if isinstance(val, int):
            return "== %d" % (val)
        op = "=="
        if isinstance(val, str):
            if "*" in val[1:-1]:  # value contains * inside string - use regex match
                op = "matches regex"
                val = re.sub('(\\\\\*|\*)', '.*', val)
                if "\\" in val:
                    val = "@'(?i)%s'" % (val)
                else:
                    val = "'(?i)%s'" % (val)
                return "%s %s" % (op, self.cleanValue(val))
            elif val.startswith("*") or val.endswith("*"):
                if val.startswith("*") and val.endswith("*"):
                    op = "contains"
                    val = val[1:-1]
                elif val.startswith("*"):
                    op = "endswith"
                    val = val[1:]
                elif val.endswith("*"):
                    op = "startswith"
                    val = val[:-1]
                val = re.sub('([".^$]|(?![*?]))', '\g<1>', val)
                val = re.sub('(\\\\\*|\*)', '', val)
                val = re.sub('\\?', '.', val)
                if "\\" in val:
                    return "%s @'%s'" % (op, self.cleanValue(val))
                return "%s '%s'" % (op, self.cleanValue(val))
            elif "\\" in val:
                return "%s @'%s'" % (op, self.cleanValue(val))
        return "%s \"%s\"" % (op, self.cleanValue(val))

    def getTable(self, sigmaparser):
        if self.category == "process_creation" and len(set(sigmaparser.values.keys()) - {"Image", "ParentImage",
                                                                                         "CommandLine"}) == 0:
            self.table = "SecurityEvent | where EventID == 4688 "
            self.eventid = "4688"
            self.tableAggJoinFields = "SubjectLogonId, Computer"
            self.tableAggTimeField = "TimeGenerated"
        elif self.category == "process_creation":
            self.table = "SysmonEvent"
            self.eventid = "1"
        elif self.service and self.service.lower() == "security":
            self.table = "SecurityEvent"
        elif self.service and self.service.lower() == "sysmon":
            self.table = "SysmonEvent"
        elif self.service and self.service.lower() == "powershell":
            self.table = "Event"
        elif self.service and self.service.lower() == "office365":
            self.table = "OfficeActivity"
        elif self.service and self.service.lower() == "azuread":
            self.table = "AuditLogs"
        elif self.service and self.service.lower() == "azureactivity":
            self.table = "AzureActivity"
        else:
            if self.service:
                if "-" in self.service:
                    self.table = "-".join([item.capitalize() for item in self.service.split("-")])
                elif "_" in self.service:
                    self.table = "_".join([item.capitalize() for item in self.service.split("_")])
                else:
                    if self.service.islower() or self.service.isupper():
                        self.table = self.service.capitalize()
                    else:
                        self.table = self.service
            elif self.product:
                if "-" in self.product:
                    self.table = "-".join([item.capitalize() for item in self.product.split("-")])
                elif "_" in self.product:
                    self.table = "_".join([item.capitalize() for item in self.product.split("_")])
                else:
                    if self.product.islower() or self.product.isupper():
                        self.table = self.product.capitalize()
                    else:
                        self.table = self.product
            elif self.category:
                if "-" in self.category:
                    self.table = "-".join([item.capitalize() for item in self.category.split("-")])
                elif "_" in self.category:
                    self.table = "_".join([item.capitalize() for item in self.category.split("_")])
                else:
                    if self.category.islower() or self.category.isupper():
                        self.table = self.category.capitalize()
                    else:
                        self.table = self.category

    def generate(self, sigmaparser):
        try:
            self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigmaparser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigmaparser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            self.category = None
            self.product = None
            self.service = None
        detection = sigmaparser.parsedyaml.get("detection", {})
        if "keywords" in detection.keys():
            return super().generate(sigmaparser)
        if self.table is None:
            self.getTable(sigmaparser)

        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.table is None:
            raise NotSupportedError("No table could be determined from Sigma rule")
        if self.category == "process_creation" and self.sysmon:
            parse_string = self.map_sysmon_schema(self.eventid)
            before = "%s | parse EventData with * %s | where EventID == \"%s\" | where " % (self.table, parse_string, self.eventid)
        elif self.sysmon:
            parse_string = self.map_sysmon_schema(self.eventid)
            before = "%s | parse EventData with * %s | where " % (self.table, parse_string)
        # elif self.category == "process_creation" and not self._has_logsource_event_cond:
        #     before = "%s | where EventID == \"%s\" | where " % (self.table, self.eventid)
        else:
            before = "%s | where " % self.table
        if parsed.parsedAgg != None and parsed.parsedAgg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            window = parsed.parsedAgg.parser.parsedyaml["detection"].get("timeframe", "30m")
            before = """
            let lookupWindow = %s;
            let lookupBin = lookupWindow / 2.0;
            """ % (window) + before
        return before

    def generateMapItemNode(self, node):
        """
        ALA queries, like ATP, refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        key = self.fieldNameMapping(key, value)
        if type(value) == list:         # handle map items with values list like multiple OR-chained conditions
            return "(" + self.generateORNode(
                    [(key, v) for v in value]
                    ) + ")"
        elif key == "EventID":            # EventIDs are not reflected in condition but in table selection
            if self.service == "sysmon":
                self.table = "SysmonEvent"
                self.eventid = value
            elif self.service == "powershell":
                self.table = "Event"
            elif self.service == "security":
                self.table = "SecurityEvent"
            elif self.service == "system":
                self.table = "Event"
            return self.mapExpression % (key, value)
        elif type(value) in [SigmaTypeModifier, SigmaContainsModifier, SigmaRegularExpressionModifier, SigmaStartswithModifier, SigmaEndswithModifier]:
            return self.generateMapItemTypedNode(key, value)
        elif type(value) in (str, int):    # default value processing'
            #default_filters = ["endswith", "contains", "startswith", "re"]
            # if any([item for item in default_filters if item in key]):
            #     key = re.sub(key, default_filters, "")
            #     return self.regexExpression % (key, self.cleanValue(value))
            # else:
            #     value_mapping = self.default_value_mapping
            value_mapping = self.default_value_mapping
            mapping = (key, value_mapping)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, self.cleanValue(value))]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(self.cleanValue(val)))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)

        elif value is None:
            return self.nullExpression % (key, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemTypedNode(self, fieldname, value):
        return "%s %s" % (fieldname, self.generateTypedValueNode(value))

    def generateTypedValueNode(self, node):
        try:
            val = str(node)
            if "*" in val:
                val = re.sub('\\*', '.*', val)
            return self.typedValueExpression[type(node)] % (val)
        except KeyError:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(node.identifier))

    def generateAggregationQuery(self, agg, searchId):
        condtoken = SigmaConditionTokenizer(searchId)
        condparsed = SigmaConditionParser(agg.parser, condtoken)
        backend = AzureLogAnalyticsBackend(agg.config)

        # these bits from generate() should be moved to __init__
        try:
            backend.category = agg.parser.parsedyaml['logsource'].setdefault('category', None)
            backend.product = agg.parser.parsedyaml['logsource'].setdefault('product', None)
            backend.service = agg.parser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            backend.category = None
            backend.product = None
            backend.service = None
        backend.getTable(agg.parser)

        query = backend.generateQuery(condparsed)
        before = backend.generateBefore(condparsed)
        return before + query

    # follow the join/time window pattern
    # https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/join-timewindow
    def generateNear(self, agg):
        includeQueries = []

        includeCount = 0
        for includeCount, include in enumerate(agg.include, start=1):
            iq = self.generateAggregationQuery(agg, include)
            iq += """
                | extend End{timeIndex}={timeField},
                    TimeKey = range(
                        bin({timeField} - lookupWindow, lookupBin),
                        bin({timeField}, lookupBin),
                        lookupBin)
                | mv-expand TimeKey to typeof(datetime)""".format(
                    timeField=self.tableAggTimeField,
                    timeIndex=includeCount,
                )
            includeQueries.append(iq)

        ret = " | extend Start={timeField}, TimeKey = bin({timeField}, lookupBin) | join kind=inner (\n  ".format(
            timeField=self.tableAggTimeField,
        )
        ret += ") on {joinFields}, TimeKey | join kind=inner (\n  ".format(
            joinFields=self.tableAggJoinFields,
        ).join(includeQueries)
        ret += ") on {joinFields}, TimeKey\n| where ".format(
            joinFields=self.tableAggJoinFields,
        )
        ret += " and ".join([
            "(End%d - Start) between (0min .. lookupWindow)" % (endIndex + 1) for endIndex in range(includeCount)
        ])

        return ret

    def generateAggregation(self, agg):
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            if agg.exclude:
                raise NotSupportedError("This backend doesn't currently support 'near' with excludes")
            if self.tableAggJoinFields == None or self.tableAggTimeField == None:
                raise NotSupportedError("This backend doesn't currently support 'near' for this table")
            return self.generateNear(agg)
        if agg.aggfunc_notrans != 'count' and agg.aggfield is None:
            raise NotSupportedError(
                "The '%s' aggregation operator " % agg.aggfunc_notrans
                + "must have an aggregation field for the %s backend" % self.identifier
            )
        if agg.aggfunc_notrans == 'count' and agg.aggfield is not None:
            agg_func = "dcount"
        else:
            agg_func = agg.aggfunc_notrans

        self._agg_var = agg_func + ("_" + agg.aggfield) if agg.aggfield else "var"
        if not self._fields:
            by_clause = "by {grp}".format(grp=agg.groupfield if agg.groupfield else "")
        else:
            if agg.aggfield_notrans in self._fields:
                self._fields.remove(agg.aggfield_notrans)
            by_clause = "by {grp}".format(grp=", ".join(self._map_fields(self._fields)))
        return (
            " | summarize {var} = {func}({fld}) {by} | where {var} {op} {cond}".format(
                var=self._agg_var,
                func=agg_func,
                fld=agg.aggfield or "",
                by=by_clause,
                op=agg.cond_op,
                cond=agg.condition,
            )
        )

    def _map_conditional_field(self, fieldname):
        mapping = self.sigmaconfig.fieldmappings.get(fieldname)
        # if there is a conditional mapping for this fieldname
        # and it matches the current event id, get the mapping
        if (
            mapping
            and isinstance(mapping, ConditionalFieldMapping)
            and "EventID" in mapping.conditions
        ):
            fieldname = mapping.conditions["EventID"].get(self.eventid, [fieldname])[0]
        elif self._field_map:
            # Fall back to default internal map if no config
            return self._field_map.get(fieldname, fieldname)
        return fieldname

class AzureAPIBackend(AzureLogAnalyticsBackend):
    """Converts Sigma rule into Azure Log Analytics Rule."""
    identifier = "ala-rule"
    active = True
    options = SingleTextQueryBackend.options + (
            ("sysmon", False, "Generate Sysmon event queries for generic rules", None),
            )

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.techniques = self._load_mitre_file("techniques")

    def find_technique(self, key_ids):
        for key_id in set(key_ids):
            if not key_id:
                continue
            for technique in self.techniques:
                if key_id == technique.get("technique_id", ""):
                    yield technique
                if "." in key_id and key_id.split(".")[0] == technique.get("technique_id", ""):
                    yield technique

    def _load_mitre_file(self, mitre_type):
        try:
            backend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config", "mitre"))
            path = os.path.join(backend_dir, "{}.json".format(mitre_type))
            with open(path) as config_file:
                config = json.load(config_file)
                return config
        except (IOError, OSError) as e:
            print("Failed to open {} configuration file '%s': %s".format(path, str(e)), file=sys.stderr)
            return []
        except json.JSONDecodeError as e:
            print("Failed to parse {} configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            return []

    def skip_tactics_or_techniques(self, src_technics, src_tactics):
        tactics = set()
        technics = set()

        local_storage_techniques = {item["technique_id"]: item for item in self.find_technique(src_technics)}

        for key_id in src_technics:
            if "." in key_id:
                src_tactic = local_storage_techniques.get(key_id.split(".")[0], {}).get("tactic")
            else:
                src_tactic = local_storage_techniques.get(key_id, {}).get("tactic")
            if not src_tactic:
                continue
            src_tactic = set(src_tactic)

            for item in src_tactics:
                if item in src_tactic:
                    technics.add(key_id)
                    tactics.add(item)

        return sorted(tactics), sorted(technics)

    def parse_severity(self, old_severity):
        if old_severity.lower() == "critical":
            return "high"
        return old_severity

    def get_tactics_and_techniques(self, tags):
        tactics = list()
        technics = list()

        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[t][0-9]{4}", tag, re.IGNORECASE):
                technics.append(tag.title())
            else:
                if "_" in tag:
                    tag = tag.replace("_", " ")
                tag = tag.title()
                tactics.append(tag)

        return tactics, technics

    def timeframeToDelta(self, timeframe):
        time_unit = timeframe[-1:]
        duration = int(timeframe[:-1])
        return (
            time_unit == "s" and timedelta(seconds=duration) or
            time_unit == "m" and timedelta(minutes=duration) or
            time_unit == "h" and timedelta(hours=duration) or
            time_unit == "d" and timedelta(days=duration) or
            None
        )

    def iso8601_duration(self, delta):
        if not delta:
            return "PT0S"
        if not delta.seconds:
            return "P%dD" % (delta.days)
        days = delta.days and "%dD" % (delta.days) or ""
        hours = delta.seconds // 3600 % 24 and "%dH" % (delta.seconds // 3600 % 24) or ""
        minutes = delta.seconds // 60 % 60 and "%dM" % (delta.seconds // 60 % 60) or ""
        seconds = delta.seconds % 60 and "%dS" % (delta.seconds % 60) or ""
        return "P%sT%s%s%s" % (days, hours, minutes, seconds)

    def create_rule(self, config):
        tags = config.get("tags", [])

        tactics, technics = self.get_tactics_and_techniques(tags)
        tactics, technics = self.skip_tactics_or_techniques(technics, tactics)
        tactics = list(map(lambda s: s.replace(" ", ""), tactics))

        timeframe = self.timeframeToDelta(config["detection"].setdefault("timeframe", "30m"))
        queryDuration = self.iso8601_duration(timeframe)
        suppressionDuration = self.iso8601_duration(timeframe * 5)

        rule = {
                "displayName": "{} by {}".format(config.get("title"), config.get('author')),
                "description": "{} {}".format(config.get("description"), "Technique: {}.".format(",".join(technics))),
                "severity": self.parse_severity(config.get("level", "medium")),
                "enabled": True,
                "query": config.get("translation"),
                "queryFrequency": queryDuration,
                "queryPeriod": queryDuration,
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": suppressionDuration,
                "suppressionEnabled": True,
                "tactics": tactics
            }
        return json.dumps(rule)

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs)
            return rule
        else:
            raise NotSupportedError("No table could be determined from Sigma rule")

class SentinelBackend(AzureAPIBackend):
    """Converts Sigma rule into Azure Sentinel scheduled alert rule ARM template."""
    identifier = "sentinel-rule"
    active = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_sentinel_rule(configs)
            return json.dumps(rule)

    def create_sentinel_rule(self, config):
        # https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/child-resource-name-type#outside-parent-resource
        # https://docs.microsoft.com/en-us/azure/templates/microsoft.operationalinsights/workspaces?tabs=json
        # https://docs.microsoft.com/en-us/rest/api/securityinsights/alert-rules/create-or-update#scheduledalertrule
        properties = json.loads(config.get("translation"))
        properties.update({
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": False,
                    "reopenClosedIncident": False,
                    "lookbackDuration": properties['suppressionDuration'],
                    "matchingMethod": "AllEntities",
                    "groupByEntities": [],
                    "groupByAlertDetails": [],
                    "groupByCustomDetails": [],
                },
            },
            "eventGroupingSettings": {
                "aggregationKind": "SingleAlert",
            },
            "alertDetailsOverride": None,
            "customDetails": None,
            "templateVersion": "1.0.0",
        })
        rule_uuid = config.get("id", str(uuid4()))
        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "workspace": {
                    "type": "String",
                },
            },
            "resources": [
                {
                    "id": "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/" + rule_uuid + "')]",
                    "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/" + rule_uuid + "')]",
                    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                    "apiVersion": "2021-03-01-preview",

                    "kind": "Scheduled",
                    "properties": properties,
                },
            ],
        }
