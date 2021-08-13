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
from .elasticsearch import ElasticsearchQuerystringBackend
from .defaultOpensearchValues import *

class OpenSearchBackend(object):
    """OpenSearch detection rule backend."""
    active = True
    uuid_black_list = []
    options = ElasticsearchQuerystringBackend.options + (
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

    '''
    Loads appropriate mitre file and returns mappings as dict.
    '''
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

    '''
    Calls parent generate methods to retrieve Sigma rule condition as Elastic Common Schema query.
    Then calls the create_rule method to return final translated object.
    '''
    def generate(self, sigmaparser):
        # reset per-detection variables
        self.rule_threshold = {}
        translation = super().generate(sigmaparser)
        print(f'translation: {translation}\n')
        if translation:
            index = sigmaparser.get_logsource().index
            if len(index) == 0:
                index = ["apm-*-transaction", "auditbeat-*", "endgame-*", "filebeat-*", "packetbeat-*", "winlogbeat-*"]
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs, index)
            return rule

    '''
    Generates threat detection for OpenSearch monitor, which compiles tactics and techniques found in Sigma tags.
    '''
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

    '''
    Finds tactics mentioned in Sigma tags.
    '''
    def find_tactics(self, key_name=None, key_id=None):
        for tactic in self.tactics:
            if key_name and key_name == tactic.get("tactic", ""):
                return tactic
            if key_id and key_id == tactic.get("external_id", ""):
                return tactic

    '''
    Finds techniques mentioned in Sigma tags.
    '''
    def find_technique(self, key_id=None):
        for technique in self.techniques:
            if key_id and key_id == technique.get("technique_id", ""):
                return technique

    '''
    Maps Sigma severity to OpenSearch numerical severity from 1-5.
    '''
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
                        "source": f'{TRIGGER_SCRIPT}',
                        "lang": TRIGGER_LANGUAGE
                    }
                },
                "actions": []
                }
            ]

    '''
    Builds OpenSearch monitor query from translated Elastic Common Schema query.
    Only supports must and should clauses.
    '''
    def build_query(self, translation):
        translation = "(winlog.channel:\"System\" AND winlog.event_id:\"16\" OR winlog.event_data.HiveName.keyword:*\\\\AppData\\\\Local\\\\Temp\\\\SAM* OR winlog.event_data.HiveName.keyword:*.dmp)"
        # translation = "(winlog.channel:\"System\""
        parsedTranslation = translation.strip("()").split("OR")
        
        if len(parsedTranslation) == 0:
            return {}
            
        clauses = []
        
        translateIndex = 0
        while translateIndex < len(parsedTranslation):
            expression = parsedTranslation[translateIndex]
            currMatches = []
            clause = "must" # default clause is "must"; clause is "should" if multiple "or" statements

            parsedExpression = expression.split()

            # Statement was joined by "or"
            if len(parsedExpression) == 1:
                counter = 1
                tempIndex = translateIndex
                while tempIndex+1 < len(parsedTranslation) and len(parsedTranslation[tempIndex+1].split()) == 1:
                    tempIndex += 1
                    counter += 1

                # If there's more than one, use "should" clase instead of "must"
                if counter > 1:
                    clause = "should"
                    parsedExpression = []

                    # Rebuild parsed expression to join statements together and fast forward the translate index
                    for i in range(counter):
                        parsedExpression.append(parsedTranslation[translateIndex+i])
                        parsedExpression.append(None)
                    
                    translateIndex = tempIndex
            
            # Iterate through each statement and join match statements into array
            for expressionIndex in range(0, len(parsedExpression), 2):
                element = parsedExpression[expressionIndex]
                currMatches.append({
                    "match": {
                        element.split(":")[0]: element.split(":")[1]
                    }
                })

            currQuery = {
                "bool": {
                    clause: currMatches
                }
            }

            clauses.append(currQuery)
            translateIndex += 1

        # If only one type of clause, don't use nested bool object
        if len(clauses) > 1:
            return {
                        "bool": {
                            "should": clauses
                        }
                    }
        return clauses[0]

    '''
    Builds inputs field of OS monitor.
    '''
    def build_inputs(self, translation):
        return [
                {
                    "search": {
                        "indices": MONITOR_INDICES,
                        "query": {
                            "size": NUM_RESULTS,
                            "aggregations": {},
                            "query": self.build_query(translation)
                        }
                    }
                }
            ]

    '''
    Adds Sigma yml file name in references if self.put_filename_in_ref option is True.
    '''
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

    '''
    Builds the list of searchable tags. Matches against list of known tags and adds any custom tags.
    '''
    def build_tags_list(self, tags):
        tactics_list = list()
        new_tags = list()
        technics_list = list()

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
        
        return tactics_list, technics_list, new_tags

    '''
    Get the rule id of the Sigma rule. If the rule id is blank or isn't unique, generate a random one.
    '''
    def get_rule_id(self, rule_uuid):
        rule_uuid = rule_uuid.lower()
        if rule_uuid == "" or rule_uuid in self.uuid_black_list:
            rule_uuid = str(uuid4())
        self.uuid_black_list.append(rule_uuid)
        rule_id = re.sub(re.compile('[()*+!,\[\].\s"]'), "_", rule_uuid)

        return rule_id

    '''
    Gets list of references.
    '''
    def get_references(self, configs):
        references = configs.get("reference") if configs.get("reference") is not None else configs.get("references")
        references = self.build_ref_yaml(references, configs)
        return references

    '''
    Adds Sigma yml file to references.
    '''
    def build_ref_yaml(self, references, configs):
        add_ref_yml = self.build_ymlfile_ref(configs)
        if add_ref_yml:
            if references is None: # No ref
                references=[]
            if add_ref_yml in references:
                pass # else put a duplicate ref for  multi rule file
            else:
                references.append(add_ref_yml)
        
        return references

    '''
    Main method that builds OpenSearch monitor and returns it in JSON format.
    '''
    def create_rule(self, configs, index):
        rule_name = configs.get("title", "")
        
        rule_description = configs.get("description", "")
        
        inputs = self.build_inputs(configs.get("translation", ""))
        
        triggers = self.create_trigger(configs.get("level", "medium"))
        
        rule_id = self.get_rule_id(configs.get("id", ""))

        tactics_list, technics_list, new_tags = self.build_tags_list(configs.get("tags", []))   
        threat = self.create_threat_description(tactics_list, technics_list)
        
        references = self.get_references(configs)
        
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
            "sigma_meta_data": {
                "rule_id": rule_id,
                "threat": threat
            }
        }

        if references:
            rule.update({"references": references})

        return json.dumps(rule)

class OpenSearchQsBackend(OpenSearchBackend, ElasticsearchQuerystringBackend):
    '''
    Backend class containing the identifier for the -t argument. Can inherit from ElasticsearchQuerystringBackend
    since query string in both OpenSearch monitors and ElasticRule are in Elastic Common Schema.
    '''
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