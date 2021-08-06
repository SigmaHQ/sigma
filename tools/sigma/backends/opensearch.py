# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Devin Ferguson, Julien Bachmann

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
import re
from fnmatch import fnmatch
import sys
import os
from random import randrange
from distutils.util import strtobool
from uuid import uuid4

import sigma
import yaml
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier, SigmaTypeModifier
from sigma.parser.condition import ConditionOR, ConditionAND, NodeSubexpression, SigmaAggregationParser, SigmaConditionParser, SigmaConditionTokenizer

from sigma.config.mapping import ConditionalFieldMapping
from .base import BaseBackend, SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from .exceptions import NotSupportedError
from .defaultOpensearchValues import *

class DeepFieldMappingMixin(object):
    def fieldNameMapping(self, fieldname, value):
        if isinstance(fieldname, str):
            get_config = self.sigmaconfig.fieldmappings.get(fieldname)
            if not get_config and '|' in fieldname:
                fieldname = fieldname.split('|', 1)[0]
                get_config = self.sigmaconfig.fieldmappings.get(fieldname)
            if isinstance(get_config, ConditionalFieldMapping):
                condition = self.sigmaconfig.fieldmappings.get(fieldname).conditions
                for key, item in self.logsource.items():
                    if condition.get(key) and condition.get(key, {}).get(item):
                        new_fieldname = condition.get(key, {}).get(item)
                        if any(new_fieldname):
                           return super().fieldNameMapping(new_fieldname[0], value)
        return super().fieldNameMapping(fieldname, value)

    def generate(self, sigmaparser):
        self.logsource = sigmaparser.parsedyaml.get("logsource", {})
        return super().generate(sigmaparser)

class OpenSearchWildcardHandlingMixin(object):
    """
    Determine field mapping to keyword subfields depending on existence of wildcards in search values. Further,
    provide configurability with backend parameters.
    """
    options = SingleTextQueryBackend.options + (
            ("keyword_field", "keyword", "Keyword sub-field name (default is: '.keyword'). Set blank value if all keyword fields are the base(top-level) field. Additionally see 'keyword_base_fields' for more granular control of the base & subfield situation.", None),
            ("analyzed_sub_field_name", "", "Analyzed sub-field name. By default analyzed field is the base field. Therefore, use this option to make the analyzed field a subfield. An example value would be '.text' ", None),
            ("analyzed_sub_fields", None, "Fields that have an analyzed sub-field.", None),
            ("keyword_base_fields", None, "Fields that the keyword is base (top-level) field. By default analyzed field is the base field. So use this option to change that logic. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("keyword_whitelist", None, "Fields to always set as keyword. Bypasses case insensitive options. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("keyword_blacklist", None, "Fields to never set as keyword (ie: always set as analyzed field). Bypasses case insensitive options. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("case_insensitive_whitelist", None, "Fields to make the values case insensitive regex. Automatically sets the field as a keyword. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("case_insensitive_blacklist", None, "Fields to exclude from being made into case insensitive regex. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("wildcard_use_keyword", "true", "Use analyzed field or wildcard field if the query uses a wildcard value (ie: '*mall_wear.exe'). Set this to 'False' to use analyzed field or wildcard field. Valid options are: true/false", None),
            )
    reContainsWildcard = re.compile("(?:(?<!\\\\)|\\\\\\\\)[*?]").search
    uuid_regex = re.compile( "[0-9a-fA-F]{8}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{12}", re.IGNORECASE )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.matchKeyword = True
        self.CaseInSensitiveField = False
        self.keyword_field = self.keyword_field.strip().strip('.') # Prevent mistake if user added a '.' or field has spaces
        self.analyzed_sub_field_name = self.analyzed_sub_field_name.strip().strip('.') # Prevent mistake if user added a '.' or field has spaces
        try:
            self.keyword_base_fields = self.keyword_base_fields.replace(' ','').split(',')
        except AttributeError:
            self.keyword_base_fields = list()
        try:
            self.analyzed_sub_fields = self.analyzed_sub_fields.replace(' ','').split(',')
        except AttributeError:
            self.analyzed_sub_fields = list()
        try:
            self.keyword_whitelist = self.keyword_whitelist.replace(' ','').split(',')
        except AttributeError:
            self.keyword_whitelist = list()
        try:
            self.keyword_blacklist = self.keyword_blacklist.replace(' ','').split(',')
        except AttributeError:
            self.keyword_blacklist = list()
        try:
            self.case_insensitive_whitelist = self.case_insensitive_whitelist.replace(' ','').split(',')
        except AttributeError:
            self.case_insensitive_whitelist = list()
        try:
            self.case_insensitive_blacklist = self.case_insensitive_blacklist.replace(' ','').split(',')
        except AttributeError:
            self.case_insensitive_blacklist = list()
        try:
            self.wildcard_use_keyword = strtobool(self.wildcard_use_keyword.lower().strip())
        except AttributeError:
            self.wildcard_use_keyword = False

    def containsWildcard(self, value):
        """Determine if value contains wildcard."""
        if type(value) == str:
            res = self.reContainsWildcard(value)
            return res
        else:
            return False

    def generateMapItemNode(self, node):
        fieldname, value = node
        if fieldname.lower().find("hash") != -1:
            if isinstance(value, list):
                res = []
                for item in value:
                    try:
                        res.extend([item.lower(), item.upper()])
                    except AttributeError:  # not a string (something that doesn't support upper/lower casing)
                        res.append(item)
                value = res
            elif isinstance(value, str):
                value = [value.upper(), value.lower()]
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def fieldNameMapping(self, fieldname, value, *agg_option):
        """
        Decide whether to use a keyword field or analyzed field. Using options on fields to make into keywords OR not and the field naming of keyword.
        Further, determine if values contain wildcards. Additionally, determine if case insensitive regex should be used. Finally,
        if field value should be quoted based on the field name decision and store it in object property.
        """
        force_keyword_whitelist = False # override everything AND set keyword and turn off case insensitivity
        force_keyword_blacklist = False # override everything AND set analyzed field and turn off case insensitivity
        force_keyword_type = False # make keyword
        keyword_subfield_name = self.keyword_field
        analyzed_subfield_name = self.analyzed_sub_field_name

        # Set naming for keyword fields
        if keyword_subfield_name == '':
            force_keyword_type = True
        elif len(self.keyword_base_fields) != 0 and any ([ fnmatch(fieldname, pattern) for pattern in self.keyword_base_fields ]):
            keyword_subfield_name = ''
        else:
            keyword_subfield_name = '.%s'%keyword_subfield_name

        # Set naming for analyzed fields
        if analyzed_subfield_name != '':
            analyzed_subfield_name = '.%s'%analyzed_subfield_name

        # force keyword on agg_option used in Elasticsearch DSL query key
        if agg_option:
            force_keyword_type = True

        # Only some analyzed subfield, so if not in this list then has to be keyword
        if len(self.analyzed_sub_fields) != 0 and not any ([ fnmatch(fieldname, pattern) for pattern in self.analyzed_sub_fields ]):
            force_keyword_type = True

        # Keyword (force) exclude
        if len(self.keyword_blacklist) != 0 and any ([ fnmatch(fieldname, pattern.strip()) for pattern in self.keyword_blacklist ]):
            force_keyword_blacklist = True
        # Keyword (force) include
        elif len(self.keyword_whitelist) != 0 and any ([ fnmatch(fieldname, pattern.strip()) for pattern in self.keyword_whitelist ]):
            force_keyword_whitelist = True

        # Set case insensitive regex
        if not (len( self.case_insensitive_blacklist ) != 0 and any([ fnmatch( fieldname, pattern ) for pattern in self.case_insensitive_blacklist ])) and len( self.case_insensitive_whitelist ) != 0 and any([ fnmatch( fieldname, pattern ) for pattern in self.case_insensitive_whitelist ]):
            self.CaseInSensitiveField = True
        else:
            self.CaseInSensitiveField = False

        # Set type and value
        if force_keyword_blacklist:
            self.matchKeyword = False
            self.CaseInSensitiveField = False
        elif force_keyword_whitelist:
            self.matchKeyword = True
            self.CaseInSensitiveField = False
        elif force_keyword_type:
            self.matchKeyword = True
        elif self.CaseInSensitiveField:
            self.matchKeyword = True
        elif self.wildcard_use_keyword and ( (type(value) == list and any(map(self.containsWildcard, value))) or self.containsWildcard(value) ):
            self.matchKeyword = True
        elif isinstance(value, SigmaRegularExpressionModifier):
            self.matchKeyword = True
        else:
            self.matchKeyword = False

        # Return compiled field name
        if self.matchKeyword:
            return '%s%s'%(fieldname, keyword_subfield_name)
        else:
            return '%s%s'%(fieldname, analyzed_subfield_name)

    def makeCaseInSensitiveValue(self, value):
        """
        Returns dictionary of if should be a regex (`is_regex`) and if regex the query value ('value')
        Converts the query(value) into a case insensitive regular expression (regex). ie: 'http' would get converted to '[hH][tT][pP][pP]'
        Adds the beginning and ending '/' to make regex query if still determined that it should be a regex
        """
        if value and not value == 'null' and not re.match(r'^/.*/$', value) and (re.search('[a-zA-Z]', value) and not re.match(self.uuid_regex, value) or self.containsWildcard(value)):  # re.search for alpha is fastest:
            # Turn single ending '\\' into non escaped (ie: '\\*')
            #value = re.sub( r"((?<!\\)(\\))\*$", "\g<1>\\*", value )
            # Make upper/lower
            value = re.sub( r"[A-Za-z]", lambda x: "[" + x.group( 0 ).upper() + x.group( 0 ).lower() + "]", value )
            # Turn `.` into wildcard, only if odd number of '\'(because this would mean already escaped)
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))\.", "\g<1>\.", value )
            # Turn `*` into wildcard, only if odd number of '\'(because this would mean already escaped)
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))\*", "\g<1>.*", value )
            # Escape additional values that are treated as specific "operators" within Elastic. (ie: @, ?, &, <, >, and ~)
            # reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/regexp-syntax.html#regexp-optional-operators
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))([@?&~<>])", "\g<1>\\\\\g<4>", value )
            # Validate regex
            try:
                re.compile(value)
                return {'is_regex': True, 'value': value}
            # Regex failed
            except re.error:
                raise TypeError( "Regular expression validation error for: '%s')" %str(value) )
        else:
            return { 'is_regex': False, 'value': value }

class OpenSearchQuerystringBackend(DeepFieldMappingMixin, OpenSearchWildcardHandlingMixin, SingleTextQueryBackend):
    """Converts Sigma rule into OpenSearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([\s+\\-=!(){}\\[\\]^\"~:/]|(?<!\\\\)\\\\(?![*?\\\\])|\\\\u|&&|\\|\\|)")
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "%s"
    typedValueExpression = {
                SigmaRegularExpressionModifier: "/%s/"
            }
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s:%s"
    mapListsSpecialHandling = False

    def generateValueNode(self, node):
        result = super().generateValueNode(node)
        if result == "" or result.isspace():
            return '""'
        else:
            if self.matchKeyword:   # don't quote search value on keyword field
                if self.CaseInSensitiveField:
                    make_ci = self.makeCaseInSensitiveValue(result)
                    result = make_ci.get('value')
                    if make_ci.get('is_regex'): # Determine if still should be a regex
                        result = "/%s/" % result # Regex place holders for regex
                return result
            else:
                return "\"%s\"" % result

    def generateNOTNode(self, node):
        expression = super().generateNode(node.item)
        if expression:
            return "(%s%s)" % (self.notToken, expression)

    def generateSubexpressionNode(self, node):
        """Check for search not bound to a field and restrict search to keyword fields"""
        nodetype = type(node.items)
        if nodetype in { ConditionAND, ConditionOR } and type(node.items.items) == list and { type(item) for item in node.items.items }.issubset({str, int}):
            newitems = list()
            for item in node.items:
                newitem = item
                if type(item) == str:
                    if not item.startswith("*"):
                        newitem = "*" + newitem
                    if not item.endswith("*"):
                        newitem += "*"
                    newitems.append(newitem)
                else:
                    newitems.append(item)
            newnode = NodeSubexpression(nodetype(None, None, *newitems))
            self.matchKeyword = True
            result = "\\*.keyword:" + super().generateSubexpressionNode(newnode)
            self.matchKeyword = False       # one of the reasons why the converter needs some major overhaul
            return result
        else:
            return super().generateSubexpressionNode(node)

class OpenSearchBackend(object):
    """Elasticsearch detection rule backend"""
    active = True
    uuid_black_list = []
    options = OpenSearchQuerystringBackend.options + (
                ("put_filename_in_ref", False, "Want to have yml name in reference ?", None),
                ("convert_to_url", False, "Want to convert to a URL ?", None),
                ("path_to_replace", "../", "The local path to replace with dest_base_url", None),
                ("dest_base_url", "https://github.com/SigmaHQ/sigma/tree/master/", "The URL prefix", None),
                ("custom_tag", None , "Add custom tag. for multi split with a comma tag1,tag2 ", None),
            )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tactics = self._load_mitre_file("tactics")
        self.techniques = self._load_mitre_file("techniques")
        self.rule_threshold = {}

    def _load_mitre_file(self, mitre_type):
        try:
            backend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config", "mitre"))
            path = os.path.join(backend_dir,"{}.json".format(mitre_type))
            with open(path, 'r') as config_file:
                config = json.load(config_file)
                return config
        except (IOError, OSError) as e:
            print("Failed to open {} configuration file '%s': %s".format(path, str(e)), file=sys.stderr)
            return []
        except json.JSONDecodeError as e:
            print("Failed to parse {} configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            return []

    def generate(self, sigmaparser):
        # reset per-detection variables
        self.rule_threshold = {}
        translation = super().generate(sigmaparser)
        if translation:
            index = sigmaparser.get_logsource().index
            if len(index) == 0:
                index = ["apm-*-transaction", "auditbeat-*", "endgame-*", "filebeat-*", "packetbeat-*", "winlogbeat-*"]
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs, index)
            return rule

    def create_threat_description(self, tactics_list, techniques_list):
        threat_list = list()
        for tactic in tactics_list:
            temp_tactics = {
                "tactic": {
                    "id": tactic.get("external_id", ""),
                    "reference": tactic.get("url", ""),
                    "name": tactic.get("tactic", "")
                },
                "framework": "MITRE ATT&CK®"
            }
            temp_techniques = list()
            for tech in techniques_list:
                if tactic.get("tactic", "") in tech.get("tactic", []):
                    temp_techniques.append({
                                "id": tech.get("technique_id", ""),
                                "name": tech.get("technique", ""),
                                "reference": tech.get("url", "")
                            })
            temp_tactics.update({"technique": temp_techniques})
            threat_list.append(temp_tactics)
        return threat_list

    def find_tactics(self, key_name=None, key_id=None):
        for tactic in self.tactics:
            if key_name and key_name == tactic.get("tactic", ""):
                return tactic
            if key_id and key_id == tactic.get("external_id", ""):
                return tactic

    def find_technique(self, key_id=None):
        for technique in self.techniques:
            if key_id and key_id == technique.get("technique_id", ""):
                return technique

    def map_severity(self, severity):
        severity = severity.lower()
        return SEVERITIES[severity] if severity in SEVERITIES else SEVERITIES["medium"]

    def create_trigger(self, severity):
        return [
                {
                "name": TRIGGER_NAME,
                "severity": self.map_severity(severity),
                "condition": {
                    "script": {
                        "source": f'ctx.results[{RESULTS_INDEX}].hits.total.value {TRIGGER_INEQUALITY} {TRIGGER_THRESHOLD}',
                        "lang": TRIGGER_LANGUAGE
                    }
                },
                "actions": []
                }
            ]

    # Only supports must and must_not queries
    def build_query(self):
        return {
                    "bool": {
                        "must": {
                            "match_all": {}
                        }
                    }
                }

    def build_inputs(self):
        return [
                {
                    "search": {
                        "index": MONITOR_INDICES,
                        "query": {
                            "size": 0, # don't know what this field represents, but default to 0
                            "aggregations": {},
                            "query": self.build_query()
                        }
                    }
                }
            ]

    def build_ymlfile_ref(self, configs):
        if self.put_filename_in_ref == False:  # Dont want
            return None

        yml_filename = configs.get("yml_filename")
        yml_path = configs.get("yml_path")
        if yml_filename == None or yml_path == None:
            return None
            
        if self.convert_to_url:
            yml_path = yml_path.replace('\\','/')                              #windows path to url 
            self.path_to_replace = self.path_to_replace.replace('\\','/')      #windows path to url            
            if self.path_to_replace not in yml_path: #Error to change
                return None

            new_ref = yml_path.replace(self.path_to_replace,self.dest_base_url) + '/' + yml_filename
        else:
            new_ref = yml_filename
        return new_ref

    def create_rule(self, configs, index):
        tags = configs.get("tags", [])
        tactics_list = list()
        technics_list = list()
        new_tags = list()

        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[t][0-9]{4}", tag, re.IGNORECASE):
                tech = self.find_technique(tag.title())
                if tech:
                    new_tags.append(tag.title())
                    technics_list.append(tech)
            else:
                if "_" in tag:
                    tag_list = tag.split("_")
                    tag_list = [item.title() for item in tag_list]
                    tact = self.find_tactics(key_name=" ".join(tag_list))
                    if tact:
                        new_tags.append(" ".join(tag_list))
                        tactics_list.append(tact)
                elif re.match("[ta][0-9]{4}", tag, re.IGNORECASE):
                    tact = self.find_tactics(key_id=tag.upper())
                    if tact:
                        new_tags.append(tag.upper())
                        tactics_list.append(tact)
                else:
                    tact = self.find_tactics(key_name=tag.title())
                    if tact:
                        new_tags.append(tag.title())
                        tactics_list.append(tact)
        
        if self.custom_tag:
            if ',' in self.custom_tag:
                tag_split = self.custom_tag.split(",")
                for l_tag in tag_split:
                    new_tags.append(l_tag)   
            else:    
                new_tags.append(self.custom_tag)
            
        threat = self.create_threat_description(tactics_list=tactics_list, techniques_list=technics_list)
        rule_name = configs.get("title", "")
        rule_description = configs.get("description", "")
        rule_uuid = configs.get("id", "").lower()
        if rule_uuid == "" or rule_uuid in self.uuid_black_list:
            rule_uuid = str(uuid4())
        self.uuid_black_list.append(rule_uuid)
        rule_id = re.sub(re.compile('[()*+!,\[\].\s"]'), "_", rule_uuid)
        inputs = self.build_inputs()
        triggers = self.create_trigger(configs.get("level", "medium"))
        references = configs.get("reference")
        if references is None:
            references = configs.get("references")
        
        add_ref_yml= self.build_ymlfile_ref(configs)
        if add_ref_yml:
            if references is None: # No ref
                references=[]
            if add_ref_yml in references:
                pass # else put a duplicate ref for  multi rule file
            else:
                references.append(add_ref_yml)
        
        rule = {
            "type": RULE_TYPE,
            "name": rule_name,
            "description": rule_description,
            "enabled": IS_ENABLED,
            "schedule": {
                "period": {
                    "interval": INTERVAL,
                    "unit": UNIT
                }
            },
            "inputs": inputs,
            "tags": new_tags,
            "triggers": triggers,
            "meta_data": {
                "rule_id": rule_id,
                "threat": threat
            }
        }
        if references:
            rule.update({"references": references})
        return json.dumps(rule)

class OpenSearchQsBackend(OpenSearchBackend, OpenSearchQuerystringBackend):
    identifier = "os-monitor"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generateAggregation(self, agg):
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT:
            if agg.cond_op not in [">", ">="]:
                raise NotImplementedError("Threshold rules can only handle > and >= operators")
            if agg.aggfield:
                raise NotImplementedError("Threshold rules cannot COUNT(DISTINCT %s)" % agg.aggfield)
            self.rule_threshold = {
                "field": agg.groupfield if agg.groupfield else [],
                "value": int(agg.condition) if agg.cond_op == ">=" else int(agg.condition) + 1
            }
            return ""
        raise NotImplementedError("Aggregation %s is not implemented for this backend" % agg.aggfunc_notrans)