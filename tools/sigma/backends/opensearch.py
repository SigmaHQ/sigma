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
import sys
import os
from typing import List, Tuple, Union
from uuid import uuid4

from sigma.parser.condition import SigmaAggregationParser

from .elasticsearch import ElasticsearchQuerystringBackend

class Atom:
    def __init__(self, field: str, prop: str) -> None:
        self.field = field
        self.prop = prop
    def __str__(self) -> str:
        return "Atom( {}, {} )".format(self.field.replace("\\\\", "\\"), self.prop.replace("\\\\", "\\"))

# Root of AST is always a Group
class Group:
    def __init__(self) -> None:
        pass
    def __str__(self) -> str:
        return "Group( {} )".format(str(self.ary).replace("\\\\", "\\"))

class Boolean:
    def __init__(self, expression: Union[Atom, Group]) -> None:
        self.expression = expression
    def __str__(self) -> str:
        return "Boolean( {} )".format(str(self.expression).replace("\\\\", "\\"))

class Ary:
    def __init__(self, bool1: Boolean, bool2: List[Tuple[str, Boolean]] = None) -> None:
        self.bool1 = bool1
        self.bool2 = bool2
    def __str__(self) -> str:
        return "Ary( {}, {} )".format(str(self.bool1).replace("\\\\", "\\"), [(rel, str(boolean).replace("\\\\", "\\")) for rel, boolean in self.bool2])

def group_init(self, ary: Ary):
    self.ary = ary

Group.__init__ = group_init

def parse_atom(s: str) -> Atom:
    reg = r"(?<!\\):" # (any character that's not '\') followed by ':'
    return Atom(*re.split(reg, s))

'''
Since root of AST is always a Group, call parse_group to initiate parsing of overall expression.
'''
def parse_group(s: str) -> Group:
    return Group(parse_ary(s[1:-1]))

'''
Expand special group in form of A:(B OR C) to (A:B OR A:C)
'''
def expand_group(s: str) -> str:
    reg = r"(?<!\\):" # (any character that's not '\') followed by ':'

    field, props = re.split(reg, s.strip("()")) # props = (prop1 OR prop2...)
    props = props.strip("()").split() # Further split props
    newGroup = []

    for index in range(len(props)):
        element = props[index]
        if element not in ["AND", "OR"]:
            newGroup.append(f'{field}:{element}')
        else:
            newGroup.append(element)

    return "(" + " ".join(newGroup) + ")"

def parse_boolean(s: str) -> Boolean:
    if "(" not in s:
        expression = parse_atom(s)
    else:
        if s[0] != '(':
            s = expand_group(s)
        expression = parse_group(s)

    return Boolean(expression)

def parse_ary(s: str) -> Ary:
    lst = []
    left = right = level = 0

    while left < len(s):
        # Going down one level
        if right < len(s) and s[right] == '(':
            level += 1

        # Going up one level
        elif right < len(s) and s[right] == ')':
            level -= 1

        # s[left:right] is parse-able
        elif right == len(s) or (s[right] == ' ' and level == 0):
            section = s[left:right]

            # Handle Boolean case
            if section not in ["AND", "OR"]:
                section = parse_boolean(section)

            lst.append(section)
            left = right + 1

        right += 1

    # [Bool, Rel, Bool, Rel, Bool,...] => Bool, [(Rel, Bool), (Rel, Bool),...]
    bool1 = lst[0]
    bool2 = []

    for i in range(1, len(lst), 2):
        tupe = (lst[i], lst[i + 1])
        bool2.append(tupe)
    
    return Ary(bool1, bool2)

def translate_atom(atom: Atom) -> dict:
    return {
        "match": {
            atom.field: atom.prop
        }
    }

def translate_group(group: Group) -> dict:
    return translate_ary(group.ary)

def translate_boolean(boolean: Boolean) -> dict:
    if type(boolean.expression) is Atom:
        return translate_atom(boolean.expression)

    return translate_group(boolean.expression)

'''
Combining ary.bool1 and ary.bool2 into array of Boolean grouped by ANDs and split by ORs.
''' 
def convert_bool_array(bool1: Boolean, boolArr: List[Tuple[str, Boolean]]) -> List[List[Boolean]]:
    result = [[bool1]]
    resultIndex = 0
    
    for rel, boolean in boolArr:
        if rel == "AND":
            if resultIndex == len(result):
                result.append([boolean])
            else:
                result[resultIndex].append(boolean)
        else:
            resultIndex += 2
            result.append([boolean])

    return result

'''
Group atomic match statements together into parent clause and wrap inside bool statement.
Maintain group match statements, which are already wrapped in bool statement.
'''
def adjust_matches(matches: List[dict], clause) -> List[dict]:
    atomicMatches = []
    combinedAtomicMatches = []
    groupMatches = []

    # Determine if current statement is an atomic match or bool group statement
    for index in range(len(matches)):
        match = matches[index]
        if "match" in match.keys():
            atomicMatches.append(match)
        else:
            groupMatches.append(match)

    # If any atomic matches, combine under parent clause wrapped in a single bool statement
    if atomicMatches:
        # If there's only one atomic match, it should be wrapped in a bool-must regardless of the parent clause
        clause = "must" if len(atomicMatches) == 1 else clause

        combinedAtomicMatches = [{
                "bool": {
                    clause: atomicMatches
                }
            }]
    
    return combinedAtomicMatches + groupMatches

def contains_group(booleanArr: List[Boolean]) -> bool:
    for boolean in booleanArr:
        if type(boolean.expression) is Group:
            return True
    
    return False

def translate_ary(ary: Ary) -> dict:
    parsedTranslation = convert_bool_array(ary.bool1, ary.bool2)

    clauses = []
    
    translateIndex = 0
    while translateIndex < len(parsedTranslation):
        parsedExpression = parsedTranslation[translateIndex]
        currMatches = []
        clause = "must" # default clause is "must"; clause is "should" if multiple consecutive "or" statements

        # Statement was joined by "or"
        if len(parsedExpression) == 1:
            counter = 1
            tempIndex = translateIndex
            while tempIndex+1 < len(parsedTranslation) and len(parsedTranslation[tempIndex+1]) == 1:
                tempIndex += 1
                counter += 1

            # If there's more than one, use "should" clause instead of "must"
            if counter > 1:
                clause = "should"
                parsedExpression = []

                # Rebuild parsed expression to join statements together and fast forward the translate index
                for i in range(counter):
                    parsedExpression += parsedTranslation[translateIndex+i]
                
                translateIndex = tempIndex
        
        # Iterate through each statement and join match statements into array
        for boolean in parsedExpression:
            currMatches.append(translate_boolean(boolean))
        
        # If bool array contains a Group which is wrapped in a bool, match statements must also be wrapped in a bool.
        if contains_group(parsedExpression):
            currMatches = adjust_matches(currMatches, clause)

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
    isThreshold = False

    # Default values for fields exclusive to OpenSearch monitors
    RULE_TYPE = "monitor"
    IS_ENABLED = True
    INTERVAL = 5
    UNIT = "MINUTES"
    TRIGGER_NAME = "generated-trigger"
    SEVERITIES = {"informational": "5", "low": "4", "medium": "3", "high": "2", "critical": "1"}
    TRIGGER_SCRIPT = "ctx.results[0].hits.total.value > 0"
    TRIGGER_LANGUAGE = "painless"
    MONITOR_INDICES = ["opensearch-security-logs"]
    NUM_RESULTS = 1

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
        return self.SEVERITIES[severity] if severity in self.SEVERITIES else self.SEVERITIES["medium"]

    def create_trigger(self, severity):
        return [
                {
                "name": self.TRIGGER_NAME,
                "severity": self.map_severity(severity),
                "condition": {
                    "script": {
                        "source": f'{self.TRIGGER_SCRIPT}',
                        "lang": self.TRIGGER_LANGUAGE
                    }
                },
                "actions": []
                }
            ]

    def build_threshold(self, field, inequality, threshold):
        INEQUALITIES = {"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}

        return {
            "range": {
                field: {
                    INEQUALITIES[inequality]: threshold
                }
            }
        }

    '''
    Builds OpenSearch monitor query from translated Elastic Rule query. Forms an abstract syntax tree (AST)
    using the following repeated structures:
    - Atom = A:B
    - Rel = AND | OR
    - Ary = Bool [Rel Bool]*
    - Group = (Ary)
    - SGroup = A:(B OR C)
    - Bool = Atom | Group | SGroup

    Then translates AST into OpenSearch boolean queries.
    '''
    def build_query(self, translation):
        ast = parse_group(translation)
        translatedQuery = translate_group(ast)

        if self.isThreshold:
            translatedQuery["bool"]["filter"] = self.rule_threshold
        
        return translatedQuery

    '''
    Builds inputs field of OS monitor.
    '''
    def build_inputs(self, translation):
        return [
                {
                    "search": {
                        "indices": self.MONITOR_INDICES,
                        "query": {
                            "size": self.NUM_RESULTS,
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
            "type": self.RULE_TYPE,
            "name": rule_name,
            "description": rule_description,
            "enabled": self.IS_ENABLED,
            "schedule": {
                "period": {
                    "interval": self.INTERVAL,
                    "unit": self.UNIT
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
    identifier = "opensearch-monitor"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generateAggregation(self, agg):
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT:
            if agg.aggfield:
                raise NotImplementedError("Threshold rules cannot COUNT(DISTINCT %s)" % agg.aggfield)
            self.isThreshold = True
            self.rule_threshold = self.build_threshold(agg.groupfield, agg.cond_op, agg.condition)
            return ""
        raise NotImplementedError("Aggregation %s is not implemented for this backend" % agg.aggfunc_notrans)