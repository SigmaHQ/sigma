# Sigma parser
# Copyright 2016-2018 Thomas Patzke, Florian Roth

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

import yaml
import os
from .exceptions import SigmaCollectionParseError
from .rule import SigmaParser


MACRO_PATH = os.getcwd() + '\\macros\\'

class SigmaCollectionParser:
    """
    Parses a Sigma file that may contain multiple Sigma rules as different YAML documents.

    Special processing of YAML document if 'action' attribute is set to:

    * global: merges attributes from document in all following documents. Accumulates attributes from previous set_global documents
    * reset: resets global attributes from previous set_global statements
    * repeat: takes attributes from this YAML document, merges into previous rule YAML and regenerates the rule
    """
    def __init__(self, content, config=None, rulefilter=None, filename=None):
        if config is None:
            from sigma.configuration import SigmaConfiguration
            config = SigmaConfiguration()
        self.yamls = yaml.safe_load_all(content)
        self.yamls = self.expand_marcos(self.yamls)
        globalyaml = dict()
        self.parsers = list()
        prevrule = None
        if filename:
            try:
                globalyaml['yml_filename']=str(filename.name)
                globalyaml['yml_path']=str(filename.parent)
            except:
                filename = None
        
        for yamldoc in self.yamls:
            action = None
            try:
                action = yamldoc['action']
                del yamldoc['action']
            except KeyError:
                pass

            if action == "global":
                deep_update_dict(globalyaml, yamldoc)
            elif action == "reset":
                globalyaml = dict()
                if filename:
                    globalyaml['yml_filename']=str(filename.name)
                    globalyaml['yml_path']=str(filename.parent) 
            elif action == "repeat":
                if prevrule is None:
                    raise SigmaCollectionParseError("action 'repeat' is only applicable after first valid Sigma rule")
                newrule = prevrule.copy()
                deep_update_dict(newrule, yamldoc)
                if rulefilter is None or rulefilter is not None and not rulefilter.match(newrule):
                    self.parsers.append(SigmaParser(newrule, config))
                    prevrule = newrule
            else:
                deep_update_dict(yamldoc, globalyaml)
                if rulefilter is None or rulefilter is not None and rulefilter.match(yamldoc):
                    self.parsers.append(SigmaParser(yamldoc, config))
                    prevrule = yamldoc
        self.config = config

    
    def expand_marcos(self, yamls):
        """Expands Macros as defined in the Macro folder
        
        That is, instead of redefining how to detect Powershell everytime, 
        the macro can define it instead.
        This allows the author to focus on what Powershell does rather than 
        worry about renamed executables.
        """
        def expand_condition(condition, condition_substitutions):
            if condition_substitutions:
                for key in condition_substitutions:
                    if ' or ' in condition_substitutions[key].lower():
                        condition = condition.replace(key, '('+ condition_substitutions[key] + ')')
                    else:
                        condition = condition.replace(key, condition_substitutions[key])
            return condition

        def load_macro(macro_name, data_source):
            with open(MACRO_PATH + macro_name + '.yml') as f:
                macro_yaml_all = yaml.safe_load_all(f)
            
                for macro_yaml in macro_yaml_all:
                    if macro_yaml['logsource']['category'] == data_source['category'] and \
                        macro_yaml['logsource']['product'] == data_source['product']:
                        # Detection parts are renamed to avoid conflicts with other macros or rules
                        detection_dict = {f"MACRO_{macro_name}_{k}":v for k,v in macro_yaml['detection'].items() if k != "condition"}
                        
                        condition_substitutions = {k:f"MACRO_{macro_name}_{k}" for k in macro_yaml['detection'] if k != "condition"}
                        condition_string = expand_condition(macro_yaml['detection']['condition'], condition_substitutions)
                    
                    elif macro_yaml['logsource']['category'] == "generic" and \
                        macro_yaml['logsource']['product'] == "generic":
                        detection_dict_generic = {f"MACRO_{macro_name}_{k}":v for k,v in macro_yaml['detection'].items() if k != "condition"}
                        
                        condition_substitutions = {k:f"MACRO_{macro_name}_{k}" for k in macro_yaml['detection'] if k != "condition"}
                        condition_string_generic = expand_condition(macro_yaml['detection']['condition'], condition_substitutions)

            detection_dict = detection_dict if detection_dict else detection_dict_generic
            condition_string = condition_string if condition_string else condition_string_generic
            return detection_dict, condition_string

        result_yaml = []
        for part in yamls:
            if 'detection' in part:
                condition_substitutions = {}
                keys_to_delete = []
                new_detections = {}

                logsource = {'category': 'generic', 'product': 'generic'}
                if 'logsource' in part:
                    logsource = part['logsource']

                for key in part['detection']:
                    if part['detection'][key] == 'macro':
                        detection_dict, condition_string = load_macro(key, logsource)
                        keys_to_delete.append(key)
                        new_detections.update(detection_dict)
                        condition_substitutions[key] = condition_string
                
                part['detection'].update(new_detections)
                for key in keys_to_delete:
                    del part['detection'][key]
                # Update condition with macro components
                part['detection']["condition"] = expand_condition(
                    part['detection']["condition"], condition_substitutions)
            result_yaml.append(part)

        return result_yaml
    
    def generate(self, backend):
        """Calls backend for all parsed rules"""
        return filter(
                lambda x: bool(x),      # filter None's and empty strings
                [ backend.generate(parser) for parser in self.parsers ]
                )

    def __iter__(self):
        return iter([parser.parsedyaml for parser in self.parsers])

def deep_update_dict(dest, src):
    for key, value in src.items():
        if isinstance(value, dict) and key in dest and isinstance(dest[key], dict):     # source is dict, destination key already exists and is dict: merge
                deep_update_dict(dest[key], value)
        else:
            dest[key] = value
