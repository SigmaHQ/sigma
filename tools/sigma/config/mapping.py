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

from sigma.parser.condition import ConditionOR, NodeSubexpression, ConditionNULLValue
from .exceptions import SigmaConfigParseError, FieldMappingError

# Field Mapping Definitions
def FieldMapping(source, target=None):
    """Determines target type and instantiate appropriate mapping type"""
    if target == None:
        return SimpleFieldMapping(source, source)
    elif type(target) == str:
        return SimpleFieldMapping(source, target)
    elif type(target) == list:
        return MultiFieldMapping(source, target)
    elif type(target) == dict:
        return ConditionalFieldMapping(source, target)

class SimpleFieldMapping:
    """1:1 field mapping"""
    target_type = str

    def __init__(self, source, target):
        """Initialization with generic target type check"""
        if type(target) != self.target_type:
            raise TypeError("Target type mismatch: wrong mapping type for this target")
        self.source = source
        self.target = target

    def resolve(self, key, value, sigmaparser):
        """Return mapped field name"""
        return (self.target, value)

    def resolve_fieldname(self, fieldname, sigmaparser=None):
        return self.target

    def __str__(self):  # pragma: no cover
        return "SimpleFieldMapping: {} -> {}".format(self.source, self.target)

class MultiFieldMapping(SimpleFieldMapping):
    """1:n field mapping that expands target field names into OR conditions"""
    target_type = list

    def resolve(self, key, value, sigmaparser):
        """Returns multiple target field names as OR condition"""
        cond = ConditionOR()
        for fieldname in self.target:
            cond.add((fieldname, value))
        return NodeSubexpression(cond)

    def __str__(self):  # pragma: no cover
        return "MultiFieldMapping: {} -> [{}]".format(self.source, ", ".join(self.target))

class ConditionalFieldMapping(SimpleFieldMapping):
    """
    Conditional field mapping:
    * key contains field=value condition, value target mapping
    * key "default" maps when no condition matches
    * if no condition matches and there is no default, don't perform mapping
    """
    target_type = dict

    def __init__(self, source, target):
        """Init table between condition field names and values"""
        super().__init__(source, target)
        self.conditions = dict()    # condition field -> condition value -> target fields
        self.default = None
        for condition, target in self.target.items():
            try:                    # key contains condition (field=value)
                field, value = condition.split("=")
                self.add_condition(field, value, target)
            except ValueError as e:      # no, condition - "default" expected
                if condition == "default":
                    if self.default == None:
                        if type(target) == str:
                            self.default = [ target ]
                        elif type(target) == list:
                            self.default = target
                        else:
                            raise SigmaConfigParseError("Default mapping must be single value or list")
                    else:
                        raise SigmaConfigParseError("Conditional field mapping can have only one default value, use list for multiple target mappings")
                else:
                    raise SigmaConfigParseError("Expected condition or default") from e

    def add_condition(self, field, value, target):
        if field not in self.conditions:
            self.conditions[field] = dict()
        if value not in self.conditions[field]:
            self.conditions[field][value] = list()
        if type(target) == str:
            self.conditions[field][value].append(target)
        elif type(target) == list:
            self.conditions[field][value].extend(target)

    def _targets(self, sigmaparser):
        # build list of matching target mappings
        targets = set()
        for condfield in self.conditions:
            if condfield in sigmaparser.values:
                rulefieldvalues = sigmaparser.values[condfield]
                for condvalue in self.conditions[condfield]:
                    if condvalue in rulefieldvalues:
                        targets.update(self.conditions[condfield][condvalue])
        return targets

    def resolve(self, key, value, sigmaparser):
        targets = self._targets(sigmaparser)
        if len(targets) == 0:       # no matching condition, try with default mapping
            if self.default != None:
                targets = self.default

        if len(targets) == 1:     # result set contains only one target, return mapped item (like SimpleFieldMapping)
            if value is None:
                return ConditionNULLValue(val=list(targets)[0])
            else:
                return (list(targets)[0], value)
        elif len(targets) > 1:        # result set contains multiple targets, return all linked as OR condition (like MultiFieldMapping)
            cond = ConditionOR()
            for target in targets:
                if value is None:
                    cond.add(ConditionNULLValue(val=target))
                else:
                    cond.add((target, value))
            return NodeSubexpression(cond)
        else:                       # no mapping found
            if value is None:
                return ConditionNULLValue(val=key)
            else:
                return (key, value)

    def resolve_fieldname(self, fieldname, sigmaparser=None):
        if sigmaparser is None:
            if self.default != None:
                return self.default
            else:
                return fieldname
        else:
            targets = self._targets(sigmaparser)
            if len(targets) == 0:
                return self.default
            else:
                return targets.pop()       # TODO: this case should be documented

    def __str__(self):  # pragma: no cover
        return "ConditionalFieldMapping: {} -> {}".format(self.source, self.target)

# Field mappimg chain
class FieldMappingChain(object):
    """
    Chain of field mappings and fields used for calculation of a field mapping in chained conversion
    configurations.

    A chain of field mappings may fan out, as one field can map into multiple target fields and these
    must be propagated further. As the whole chain must be completed at configuration parse time, a
    restriction applies to conditional field mappings. These are calculated at rule conversion time and
    therefore it is not possible to decide further mappings after conditionals and these may only appear
    in the last configuration. This case could be solved by calculation of field mappings at rule conversion
    time, but it is not considered as important enough to be implemented at this time.
    """
    def __init__(self, fieldname):
        """Initialize field mapping chain with given field name."""
        self.fieldmappings = set([fieldname])

    def append(self, config):
        """Propagate current possible field mappings with field mapping from configuration"""
        if ConditionalFieldMapping in { type(fieldmapping) for fieldmapping in self.fieldmappings }:   # conditional field mapping appeared before, abort.
            raise FieldMappingError("Conditional field mappings are only allowed in last configuration if configurations are chained.")

        fieldmappings = set()
        if type(self.fieldmappings) == str:
            current_fieldmappings = {self.fieldmappings}
        else:
            current_fieldmappings = self.fieldmappings

        for fieldname in current_fieldmappings:
            mapping = config.get_fieldmapping(fieldname)
            if type(mapping) in (SimpleFieldMapping,  MultiFieldMapping):
                resolved_mapping = mapping.resolve_fieldname(fieldname)
                if type(resolved_mapping) is list:
                    fieldmappings.update(resolved_mapping)
                else:
                    fieldmappings.add(resolved_mapping)
            elif type(mapping) == ConditionalFieldMapping:
                fieldmappings.add(mapping)
            else:
                raise TypeError("Type '{}' is not supported by FieldMappingChain".format(str(type(mapping))))

        if len(fieldmappings) == 1:
            self.fieldmappings = fieldmappings.pop()
        else:
            self.fieldmappings = fieldmappings

    def resolve(self, key, value, sigmaparser):
        if type(self.fieldmappings) == str:     # one field mapping
            return (self.fieldmappings, value)
        elif isinstance(self.fieldmappings, ConditionalFieldMapping):
            logsource = sigmaparser.parsedyaml.get("logsource")
            condition = self.fieldmappings.conditions
            for source_type, logsource_item in logsource.items():
                if condition.get(source_type) and condition.get(source_type, {}).get(logsource_item):
                    new_field = condition.get(source_type, {}).get(logsource_item)
                    self.fieldmappings.default = new_field
            return self.fieldmappings.resolve(self.fieldmappings.source, value, sigmaparser)
        elif isinstance(self.fieldmappings, SimpleFieldMapping):
            return self.fieldmappings.resolve(key, value, sigmaparser)
        elif type(self.fieldmappings) == set:
            cond = ConditionOR()
            for mapping in self.fieldmappings:
                if type(mapping) == str:
                    cond.add((mapping, value))
                elif isinstance(mapping, SimpleFieldMapping):
                    cond.add(mapping.resolve(key, value, sigmaparser))
            return NodeSubexpression(cond)

    def resolve_fieldname(self, fieldname, sigmaparser=None):
        if type(self.fieldmappings) == str:     # one field mapping
            return self.fieldmappings
        elif isinstance(self.fieldmappings, SimpleFieldMapping):
            return self.fieldmappings.resolve_fieldname(fieldname, sigmaparser)
        elif type(self.fieldmappings) == set:
            mappings = set()
            for mapping in self.fieldmappings:
                if type(mapping) == str:
                    mappings.add(mapping)
                elif isinstance(mapping, SimpleFieldMapping):
                    resolved_mapping = mapping.resolve_fieldname(fieldname, sigmaparser)
                    if type(resolved_mapping) is list:
                        mappings.update(resolved_mapping)
                    else:
                        mappings.add(resolved_mapping)
            return list(mappings)

    def __str__(self):  # pragma: no cover
        return "FieldMappingChain: {}".format(self.fieldmappings)
