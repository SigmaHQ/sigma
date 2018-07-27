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

from sigma.parser.condition import ConditionOR
from .exceptions import SigmaConfigParseError

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

    def resolve_fieldname(self, fieldname):
        return self.target

class MultiFieldMapping(SimpleFieldMapping):
    """1:n field mapping that expands target field names into OR conditions"""
    target_type = list

    def resolve(self, key, value, sigmaparser):
        """Returns multiple target field names as OR condition"""
        cond = ConditionOR()
        for fieldname in self.target:
            cond.add((fieldname, value))
        return cond

    def resolve_fieldname(self, fieldname):
        return self.target

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

    def resolve(self, key, value, sigmaparser):
        # build list of matching target mappings
        targets = set()
        for condfield in self.conditions:
            if condfield in sigmaparser.values:
                rulefieldvalues = sigmaparser.values[condfield]
                for condvalue in self.conditions[condfield]:
                    if condvalue in rulefieldvalues:
                        targets.update(self.conditions[condfield][condvalue])
        if len(targets) == 0:       # no matching condition, try with default mapping
            if self.default != None:
                targets = self.default

        if len(targets) == 1:     # result set contains only one target, return mapped item (like SimpleFieldMapping)
            return (targets.pop(), value)
        elif len(targets) > 1:        # result set contains multiple targets, return all linked as OR condition (like MultiFieldMapping)
            cond = ConditionOR()
            for target in targets:
                cond.add((target, value))
            return cond
        else:                       # no mapping found
            return (key, value)

    def resolve_fieldname(self, fieldname):
        if self.default != None:
            return self.default
        else:
            return fieldname
