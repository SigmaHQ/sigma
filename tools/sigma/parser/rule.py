# Sigma parser
# Copyright 2016-2019 Thomas Patzke, Florian Roth

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
from .exceptions import SigmaParseError
from .condition import SigmaConditionTokenizer, SigmaConditionParser, ConditionAND, ConditionOR, ConditionNULLValue
from .modifiers import apply_modifiers

class SigmaParser:
    """Parse a Sigma rule (definitions, conditions and aggregations)"""
    def __init__(self, sigma, config):
        self.definitions = dict()
        self.values = dict()
        self.config = config
        self.parsedyaml = sigma
        self.parse_sigma()

    def parse_sigma(self):
        try:    # definition uniqueness check
            for definitionName, definition in self.parsedyaml["detection"].items():
                if definitionName != "condition":
                    self.definitions[definitionName] = definition
                    self.extract_values(definition)     # builds key-values-table in self.values
        except KeyError:
            raise SigmaParseError("No detection definitions found")

        try:    # tokenization
            conditions = self.parsedyaml["detection"]["condition"]
            self.condtoken = list()     # list of tokenized conditions
            if type(conditions) == str:
                self.condtoken.append(SigmaConditionTokenizer(conditions))
            elif type(conditions) == list:
                for condition in conditions:
                    self.condtoken.append(SigmaConditionTokenizer(condition))
        except KeyError:
            raise SigmaParseError("No condition found")

        self.condparsed = list()        # list of parsed conditions
        for tokens in self.condtoken:
            condparsed = SigmaConditionParser(self, tokens)
            self.condparsed.append(condparsed)

    def parse_definition_byname(self, definitionName, condOverride=None):
        try:
            definition = self.definitions[definitionName]
        except KeyError as e:
            raise SigmaParseError("Unknown definition '%s'" % definitionName) from e
        return self.parse_definition(definition, condOverride)

    def parse_definition(self, definition, condOverride=None):
        if type(definition) not in (dict, list):
            raise SigmaParseError("Expected map or list, got type %s: '%s'" % (type(definition), str(definition)))

        if type(definition) == list:    # list of values or maps
            if condOverride:    # condition given through rule detection condition, e.g. 1 of x
                cond = condOverride()
            else:               # no condition given, use default from spec
                cond = ConditionOR()

            subcond = None
            for value in definition:
                if type(value) in (str, int):
                    cond.add(value)
                elif type(value) in (dict, list):
                    cond.add(self.parse_definition(value))
                else:
                    raise SigmaParseError("Definition list may only contain plain values or maps")
        elif type(definition) == dict:      # map
            cond = ConditionAND()
            for key, value in definition.items():
                if "|" in key:  # field name contains value modifier
                    fieldname, *modifiers = key.split("|")
                    value = apply_modifiers(value, modifiers)
                else:
                    fieldname = key
                mapping = self.config.get_fieldmapping(fieldname)
                if isinstance(value, (ConditionAND, ConditionOR)):    # value is condition node (by transformation modifier)
                    value.items = [ mapping.resolve(key, item, self) for item in value.items ]
                    cond.add(value)
                else:           # plain value or something unexpected (catched by backends)
                    mapped = mapping.resolve(key, value, self)
                    cond.add(mapped)

        return cond

    def extract_values(self, definition):
        """Extract all values from map key:value pairs info self.values"""
        if type(definition) == list:     # iterate through items of list
            for item in definition:
                self.extract_values(item)
        elif type(definition) == dict:  # add dict items to map
            for key, value in definition.items():
                self.add_value(key, value)

    def add_value(self, key, value):
        """Add value to values table, create key if it doesn't exist"""
        if key in self.values:
            self.values[key].add(str(value))
        else:
            self.values[key] = { str(value) }

    def get_logsource(self):
        """Returns logsource configuration object for current rule"""
        try:
            ls_rule = self.parsedyaml['logsource']
        except KeyError:
            return None

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
            service = None

        return self.config.get_logsource(category, product, service)

    def get_logsource_condition(self):
        logsource = self.get_logsource()
        if logsource is None:
            return None
        else:
            if logsource.merged:    # Merged log source, flatten nested list of condition items
                kvconds = [ item for sublscond in logsource.conditions for item in sublscond ]
            else:                   # Simple log sources already contain flat list of conditions items
                kvconds = logsource.conditions

            # Apply field mappings
            mapped_kvconds = list()
            for field, value in kvconds:
                mapping = self.config.get_fieldmapping(field)
                mapped_kvconds.append(mapping.resolve(field, value, self))

            # AND-link condition items
            cond = ConditionAND()
            for kvcond in mapped_kvconds:
                cond.add(kvcond)

            # Add index condition if supported by backend and defined in log source
            index_field = self.config.get_indexfield()
            indices = logsource.index
            if len(indices) > 0 and index_field is not None:        # at least one index given and backend knows about indices in conditions
                if len(indices) > 1:      # More than one index, search in all by ORing them together
                    index_cond = ConditionOR()
                    for index in indices:
                        index_cond.add((index_field, index))
                    cond.add(index_cond)
                else:           # only one index, add directly to AND from above
                    cond.add((index_field, indices[0]))

            return cond
