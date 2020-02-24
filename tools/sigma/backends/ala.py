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

import re, json
import xml.etree.ElementTree as xml


from ..config.mapping import (
    SimpleFieldMapping, MultiFieldMapping, ConditionalFieldMapping
)
from ..parser.condition import SigmaAggregationParser
from ..parser.exceptions import SigmaParseError
from ..parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
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

    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
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

    _WIN_SECURITY_EVENT_MAP = {
        "Image": "NewProcessName",
        "ParentImage": "ParentProcessName",
        "User": "SubjectUserName",
    }

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.category = None
        self.product = None
        self.service = None
        self.table = None
        self.eventid = None
        self._parser = None
        self._fields = None
        self._agg_var = None
        self._has_logsource_event_cond = False
        if not self.sysmon and not self.sigmaconfig.config:
            self._field_map = self._WIN_SECURITY_EVENT_MAP
        else:
            self._field_map = {}
        self.typedValueExpression[SigmaRegularExpressionModifier] = "matches regex \"%s\""

    def id_mapping(self, src):
        """Identity mapping, source == target field name"""
        return src

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
        op = "=="
        if isinstance(val, str):
            if "*" in val[1:-1]:     # value contains * inside string - use regex match
                op = "matches regex"
                val = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', val)
                val = re.sub('\\*', '.*', val)
                val = re.sub('\\?', '.', val)
                if "\\" in val:
                    return "%s @\"%s\"" % (op, val)
            else:                           # value possibly only starts and/or ends with *, use prefix/postfix match
                if val.endswith("*") and val.startswith("*"):
                    op = "contains"
                    val = self.cleanValue(val[1:-1])
                elif val.endswith("*"):
                    op = "startswith"
                    val = self.cleanValue(val[:-1])
                elif val.startswith("*"):
                    op = "endswith"
                    val = self.cleanValue(val[1:])

                if "\\" in val:
                    return "%s @\"%s\"" % (op, val)

        return "%s \"%s\"" % (op, val)

    def generate(self, sigmaparser):
        self.table = None
        try:
            self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigmaparser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigmaparser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            self.category = None
            self.product = None
            self.service = None

        detection = sigmaparser.parsedyaml.get("detection", {})
        is_parent_cmd = False
        if "keywords" in detection.keys():
            return super().generate(sigmaparser)


        if self.category == "process_creation":
            self.table = "SysmonEvent"
            self.eventid = "1"
        elif self.service == "security":
            self.table = "SecurityEvent"
        elif self.service == "sysmon":
            self.table = "SysmonEvent"
        elif self.service == "powershell":
            self.table = "Event"
        else:
            if self.service:
                if "-" in self.service:
                    self.table = "-".join([item.title() for item in self.service.split("-")])
                elif "_" in self.service:
                    self.table = "_".join([item.title() for item in self.service.split("_")])
                else:
                    self.table = self.service.title()
            elif self.product:
                if "-" in self.product:
                    self.table = "-".join([item.title() for item in self.product.split("-")])
                elif "_" in self.product:
                    self.table = "_".join([item.title() for item in self.product.split("_")])
                else:
                    self.table = self.product.title()

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
        elif self.category == "process_creation" and not self._has_logsource_event_cond:
            before = "%s | where EventID == \"%s\" | where " % (self.table, self.eventid)
        else:
            before = "%s | where " % self.table
        return before

    def generateMapItemNode(self, node):
        """
        ALA queries, like ATP, refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
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
        elif type(value) in (str, int):     # default value processing
            mapping = (key, self.default_value_mapping)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, value)
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, value)]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(val))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        return super().generateMapItemNode(node)

    def generateAggregation(self, agg):
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError(
                "The 'near' aggregation operator is not "
                + f"implemented for the %s backend" % self.identifier
            )
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

    def generateAfter(self, parsed):
        del parsed
        if self._fields:
            all_fields = list(self._fields)
            if self._agg_var:
                all_fields = set(all_fields + [self._agg_var])
            project_fields = self._map_fields(all_fields)
            project_list = ", ".join(str(fld) for fld in set(project_fields))
            return " | project " + project_list
        return ""

    def _map_fields(self, fields):
        for field in fields:
            mapped_field = self._map_field(field)
            if isinstance(mapped_field, str):
                yield mapped_field
            elif isinstance(mapped_field, list):
                for subfield in mapped_field:
                    yield subfield

    def _map_field(self, fieldname):
        mapping = self.sigmaconfig.fieldmappings.get(fieldname)
        if isinstance(mapping, ConditionalFieldMapping):
            fieldname = self._map_conditional_field(fieldname)
        elif isinstance(mapping, MultiFieldMapping):
            fieldname = mapping.resolve_fieldname(fieldname, self._parser)
        elif isinstance(mapping, SimpleFieldMapping):
            fieldname = mapping.resolve_fieldname(fieldname, self._parser)
        return fieldname

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

    def create_rule(self, config):
        tags = config.get("tags", [])
        tactics = list()
        technics = list()
        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[tT][0-9]{4}", tag):
                technics.append(tag.title())
            else:
                if "_" in tag:
                    tag_list = tag.split("_")
                    tag_list = [item.title() for item in tag_list]
                    tactics.append("".join(tag_list))
                else:
                    tactics.append(tag.title())

        rule = {
                "displayName": "{} by {}".format(config.get("title"), config.get('author')),
                "description": "{} {}".format(config.get("description"), "Technique: {}.".format(",".join(technics))),
                "severity": config.get("level", "medium"),
                "enabled": True,
                "query": config.get("translation"),
                "queryFrequency": "12H",
                "queryPeriod": "12H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 1,
                "suppressionDuration": "12H",
                "suppressionEnabled": False,
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
