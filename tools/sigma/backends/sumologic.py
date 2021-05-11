# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, juju4

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
import json
import os
import re
import sys

from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.exceptions import NotSupportedError
from sigma.parser.condition import ConditionOR, SigmaAggregationParser

# Sumo specifics
# https://help.sumologic.com/05Search/Search-Query-Language
# want _index or _sourceCategory for performance
# try to get most string match on first line for performance
# further sorting can be done with extra parsing
# No regex match, must use 'parse regex' https://help.sumologic.com/05Search/Search-Query-Language/01-Parse-Operators/02-Parse-Variable-Patterns-Using-Regex
# For some strings like Windows ProcessCmdline or LogonProcess, it might be good to force case lower and upper as Windows is inconsistent in logs


class SumoLogicBackend(SingleTextQueryBackend):
    """Converts Sigma rule into SumoLogic query. Contributed by SOC Prime. https://socprime.com"""
    identifier = "sumologic"
    active = True
    config_required = False
    default_config = ["sysmon", "sumologic"]

    index_field = "_sourceCategory"
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None

    def generateAggregation(self, agg):
        # lnx_shell_priv_esc_prep.yml
        # print("DEBUG generateAggregation(): %s, %s, %s, %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op))
        if agg.groupfield == 'host':
            agg.groupfield = 'hostname'
        if agg.aggfunc_notrans == 'count() by':
            agg.aggfunc_notrans = 'count by'
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if self.keypresent:
            if not agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    return " \n| %s(%s) \n| where _count_distinct %s %s" % (
                        agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
                else:
                    return "  \n| %s | where _count %s %s" % (
                    agg.aggfunc_notrans, agg.cond_op, agg.condition)
            elif agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    return " \n| %s(%s) by %s \n| where _count_distinct %s %s" % (
                        agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)
                else:
                    return " \n| %s by %s \n| where _count %s %s" % (
                        agg.aggfunc_notrans, agg.groupfield, agg.cond_op, agg.condition)
            else:
                return " \n| %s | where _count %s %s" % (agg.aggfunc_notrans, agg.cond_op, agg.condition)
        else:
            if not agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    return " \n| parse \"[%s=*]\" as searched nodrop\n| %s(searched) \n| where _count_distinct %s %s" % (
                        agg.aggfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
                else:
                    return " \n| %s | where _count %s %s" % (
                    agg.aggfunc_notrans, agg.cond_op, agg.condition)
            elif agg.groupfield:
                if agg.aggfield:
                    agg.aggfunc_notrans = "count_distinct"
                    return " \n| parse \"[%s=*]\" as searched nodrop\n| parse \"[%s=*]\" as grpd nodrop\n| %s(searched) by grpd \n| where _count_distinct %s %s" % (
                        agg.aggfield, agg.groupfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
                else:
                    return " \n| parse \"[%s=*]\" as grpd nodrop\n| %s by grpd \n| where _count %s %s" % (
                        agg.groupfield, agg.aggfunc_notrans, agg.cond_op, agg.condition)
            else:
                return " \n| %s | where _count %s %s" % (agg.aggfunc_notrans, agg.cond_op, agg.condition)

    def generateBefore(self, parsed):
        # not required but makes query faster, especially if no FER or _index/_sourceCategory
        if self.logname:
            return "%s " % self.logname
        return ""

    def generate(self, sigmaparser):
        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']   # OS or Software
        except KeyError:
            self.product = None
        try:
            self.service = sigmaparser.parsedyaml['logsource']['service']   # Channel
        except KeyError:
            self.service = None
        try:
            self.category = sigmaparser.parsedyaml['logsource']['category']   # Channel
        except KeyError:
            self.category = None
        # FIXME! don't get backend config mapping
        self.indices = sigmaparser.get_logsource().index
        if len(self.indices) == 0:
            self.indices = None
        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            # FIXME! exclude if expression is regexp but anyway, not directly supported.
            #   Not doing if aggregation ('| count') or key ('=')
            if not (query.startswith('"') and query.endswith('"')) and not (query.startswith('(') and query.endswith(')')) and not ('|' in query) and not ('=' in query):
                query = '"%s"' % query
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            # adding parenthesis here in case 2 rules are aggregated together - ex: win_possible_applocker_bypass
            # but does not work if count, where or other piped statements...
            if '|' in result:
                return result
            else:
                return result

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO/FIXME! depending on deployment configuration, existing FER must be populate here (or backend config?)
        aFL = ["_sourceCategory", "_view", "_sourceName"]
        if self.sigmaconfig.config.get("afl_fields"):
            self.keypresent = True
            aFL.extend(self.sigmaconfig.config.get("afl_fields"))
        else:
            self.keypresent = False
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    # def generateCleanValueNodeLogsource(self, value):
    #    return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    # Sumologic: only removing '*' (in quotes, is literal. without, is wildcard) and '"'

    def cleanNode(self, node, key=None):
        if "*" in node and key and not re.search("[\s]", node):
            return node
        elif "*" in node and not key:
            return [x for x in node.split("*") if x]
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if key in ["_sourceCategory", "_sourceName"]:
                value = "*%s*" % value.lower()
                return self.mapExpression % (key, value)
            elif not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if key in ("LogName", "source"):
                    self.logname = value
                # need cleanValue if sigma entry with single quote
                return self.mapExpression % (key, self.cleanValue(value, key))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if type(value) is str:
                    new_value = list()
                    value = self.cleanNode(value)
                    if type(value) == list:
                        new_value.append(self.andToken.join([self.cleanValue(val) for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value) == 1:
                        if self.generateANDNode(new_value):
                            return self.generateANDNode(new_value)
                        else:
                            # if after cleaning node, it is empty but there is AND statement... make it true.
                            return "true"
                    else:
                        return self.generateORNode(new_value)
                else:
                    return self.generateValueNode(value)
            elif type(value) is list:
                new_value = list()
                for item in value:
                    item = self.cleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append(item[0])
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.cleanValue(val) for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            elif value is None:
                return self.nullExpression % (key, )
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # from mixins.py
    # input in simple quotes are not passing through this function. ex: rules/windows/sysmon/sysmon_vul_java_remote_debugging.yml, rules/apt/apt_sofacy_zebrocy.yml
    #   => OK only if field entry with list, not string
    #   => generateNode: call cleanValue
    def cleanValue(self, val, key=''):
        if isinstance(val, str):
            val = re.sub("[^\\\"](\")", "\\\"", val)
            if re.search("[\W\s]", val):# and not val.startswith('"') and not val.endswith('"'):  # or "\\" in node in [] or "/" in node:
                return self.valueExpression % val
        return val

    # for keywords values with space
    def generateValueNode(self, node, key=''):
        cV = self.cleanNode(str(node), key)
        if type(node) is int:
            return cV
        if type(cV) is list:
            return "(%s)" % "AND".join([self.cleanValue(item) for item in cV])
        if 'AND' in node and cV:
            return "(" + cV + ")"
        elif isinstance(node, str) and node.startswith('"') and node.endswith('"'):
            return cV
        else:
            return self.cleanValue(cV)

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item, key)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + " OR ".join(itemslist) + ")"

    # generateORNode algorithm for SumoLogicBackend class.
    def generateORNode(self, node):
        if type(node) == ConditionOR and all(isinstance(item, str) for item in node):
            new_value = list()
            for value in node:
                value = self.cleanNode(value)
                if type(value) is list:
                    new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                else:
                    new_value.append(value)
            return "(" + self.orToken.join([self.generateNode(val) for val in new_value]) + ")"
        return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"


class SumoLogicCSE(SumoLogicBackend):
    """Converts Sigma rule into SumoLogic CSE query. Contributed by SOC Prime. https://socprime.com"""
    identifier = "sumologic-cse"
    active = True
    config_required = False
    default_config = ["sysmon"]

    index_field = "metdata_product"
    reClear = None
    #reEscape = re.compile('[\\\\"]')
    andToken = " and "
    orToken = " or "
    notToken = "!"
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isEmpty(%s)"
    notNullExpression = "!isEmpty(%s)"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    interval = None
    logname = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowedFieldsList.extend(["metdata_product", "metdata_vendor"])

    def cleanValue(self, val, key=''):
        if key == 'metadata_deviceEventId' or isinstance(val, int) or val.isdigit():
            return val
        return self.valueExpression % val

    def cleanNode(self, node, key=None):
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key:
            if not self.mapListsSpecialHandling and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling and type(value) in (str, int):
                if key in ("LogName", "source"):
                    self.logname = value
                # need cleanValue if sigma entry with single quote
                return self.mapExpression % (key, self.cleanValue(value, key))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            elif value is None:
                return self.nullExpression % (key,)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        raise TypeError("Backend does not support query without key.")

    def generateMapItemListNode(self, key, value):
        if len(value) == 1:
            return self.mapExpression % (key, value[0])
        return "%s IN (%s)" % (key, ", ".join([self.cleanValue(item, key) for item in value]))


class SumoLogicCSERule(SumoLogicCSE):
    """Converts Sigma rule into SumoLogic CSE query"""
    identifier = "sumologic-cse-rule"
    active = True

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.techniques = self._load_mitre_file("techniques")
        self.allowedCategories = ["Threat Intelligence", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                                  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
                                  "Command and Control", "Exfiltration", "Impact"]
        self.defaultCategory = "Unknown/Other"
        self.results = []

    def find_technique(self, key_ids):
        for key_id in set(key_ids):
            if not key_id:
                continue
            for technique in self.techniques:
                if key_id == technique.get("technique_id", ""):
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
            elif re.match("[s][0-9]{4}", tag, re.IGNORECASE):
                continue
            else:
                if "_" in tag:
                    tag = tag.replace("_", " ")
                tag = tag.title()
                tactics.append(tag)

        return tactics, technics

    def map_risk_score(self, level):
        if level == "critical":
            return 5
        elif level == "high":
            return 4
        elif level == "medium":
            return 3
        elif level == "low":
            return 2
        return 1

    def create_rule(self, config):
        tags = config.get("tags", [])

        tactics, technics = self.get_tactics_and_techniques(tags)
        tactics, technics = self.skip_tactics_or_techniques(technics, tactics)
        tactics = list(map(lambda s: s.replace(" ", ""), tactics))
        score = self.map_risk_score(config.get("level", "medium"))
        rule = {
            "name": "{} by {}".format(config.get("title"), config.get('author')),
            "description": "{} {}".format(config.get("description"), "Technique: {}.".format(",".join(technics))),
            "enabled": True,
            "expression": """{}""".format(config.get("translation", "")),
            "assetField": "device_hostname",
            "score": score,
            "stream": "record"
        }
        if tactics and tactics[0] in self.allowedCategories:
            rule.update({"category": tactics[0]})
        else:
            rule.update({"category": "Unknown/Other"})
        self.results.append(rule)
        #return json.dumps(rule, indent=4, sort_keys=False)

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs)
            return rule
        else:
            raise NotSupportedError("No table could be determined from Sigma rule")

    def finalize(self):
        if len(self.results) == 1:
           return json.dumps(self.results[0], indent=4, sort_keys=False)
        elif len(self.results) > 1:
            return json.dumps(self.results, indent=4, sort_keys=False)



