# Sigma parser
# Copyright 2016-2017 Thomas Patzke, Florian Roth

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
import re
import logging
from sigma.parser import ConditionAND, ConditionOR

logger = logging.getLogger(__name__)

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

# Configuration
class SigmaConfiguration:
    """Sigma converter configuration. Contains field mappings and logsource descriptions"""
    def __init__(self, configyaml=None):
        if configyaml == None:
            self.config = None
            self.fieldmappings = dict()
            self.logsources = dict()
            self.logsourcemerging = SigmaLogsourceConfiguration.MM_AND
            self.defaultindex = None
            self.backend = None
        else:
            config = yaml.safe_load(configyaml)
            self.config = config

            self.fieldmappings = dict()
            try:
                for source, target in config['fieldmappings'].items():
                    self.fieldmappings[source] = FieldMapping(source, target)
            except KeyError:
                pass
            if type(self.fieldmappings) != dict:
                raise SigmaConfigParseError("Fieldmappings must be a map")

            try:
                self.logsourcemerging = config['logsourcemerging']
            except KeyError:
                self.logsourcemerging = SigmaLogsourceConfiguration.MM_AND

            try:
                self.defaultindex = config['defaultindex']
            except KeyError:
                self.defaultindex = None

            self.logsources = list()
            self.backend = None

    def get_fieldmapping(self, fieldname):
        """Return mapped fieldname if mapping defined or field name given in parameter value"""
        try:
            return self.fieldmappings[fieldname]
        except KeyError:
            return FieldMapping(fieldname)

    def get_logsource(self, category, product, service):
        """Return merged log source definition of all logosurces that match criteria"""
        matching = [logsource for logsource in self.logsources if logsource.matches(category, product, service)]
        return SigmaLogsourceConfiguration(matching, self.defaultindex)

    def set_backend(self, backend):
        """Set backend. This is used by other code to determine target properties for index addressing"""
        self.backend = backend
        if self.config != None:
            if 'logsources' in self.config:
                logsources = self.config['logsources']
                if type(logsources) != dict:
                    raise SigmaConfigParseError("Logsources must be a map")
                for name, logsource in logsources.items():
                    self.logsources.append(SigmaLogsourceConfiguration(logsource, self.defaultindex, name, self.logsourcemerging, self.get_indexfield()))

    def get_indexfield(self):
        """Get index condition if index field name is configured"""
        if self.backend != None:
            return self.backend.index_field

class SigmaLogsourceConfiguration:
    """Contains the definition of a log source"""
    MM_AND = "and"  # Merge all conditions with AND
    MM_OR  = "or"   # Merge all conditions with OR

    def __init__(self, logsource=None, defaultindex=None, name=None, mergemethod=MM_AND, indexfield=None):
        self.name = name
        self.indexfield = indexfield
        if logsource == None:               # create empty object
            self.category = None
            self.product = None
            self.service = None
            self.index = list()
            self.conditions = None
        elif type(logsource) == list and all([isinstance(o, SigmaLogsourceConfiguration) for o in logsource]):      # list of SigmaLogsourceConfigurations: merge according to mergemethod
            # Merge category, product and service
            categories = set([ ls.category for ls in logsource if ls.category != None ])
            products = set([ ls.product for ls in logsource if ls.product != None ])
            services = set([ ls.service for ls in logsource if ls.service != None])
            if len(categories) > 1 or len(products) > 1 or len(services) > 1:
                raise ValueError("Merged SigmaLogsourceConfigurations must have disjunct categories (%s), products (%s) and services (%s)" % (str(categories), str(products), str(services)))

            try:
                self.category = categories.pop()
            except KeyError:
                self.category = None
            try:
                self.product = products.pop()
            except KeyError:
                self.product = None
            try:
                self.service = services.pop()
            except KeyError:
                self.service = None

            # Merge all index patterns
            self.index = list(set([index for ls in logsource for index in ls.index]))       # unique(flat(logsources.index))
            if len(self.index) == 0 and defaultindex is not None:   # if no index pattern matched and default index is present: use default index
                if type(defaultindex) == str:
                    self.index = [defaultindex]
                elif type(defaultindex) == list and all([type(i) == str for i in defaultindex]):
                    self.index = defaultindex
                else:
                    raise TypeError("Default index must be string or list of strings")

            # "merge" index field (should never differ between instances because it is provided by backend class
            indexfields = [ ls.indexfield for ls in logsource if ls.indexfield != None ]
            try:
                self.indexfield = indexfields[0]
            except IndexError:
                self.indexfield = None

            # Merge conditions according to mergemethod
            if mergemethod == self.MM_AND:
                cond = ConditionAND()
            elif mergemethod == self.MM_OR:
                cond = ConditionOR()
            else:
                raise ValueError("Mergemethod must be '%s' or '%s'" % (self.MM_AND, self.MM_OR))
            for ls in logsource:
                if ls.conditions != None:
                    cond.add(ls.conditions)
            if len(cond) > 0:
                self.conditions = cond
            else:
                self.conditions = None
        elif type(logsource) == dict:       # create logsource configuration from parsed yaml
            if 'category' in logsource and type(logsource['category']) != str \
                    or 'product' in logsource and type(logsource['product']) != str \
                    or 'service' in logsource and type(logsource['service']) != str:
                raise SigmaConfigParseError("Logsource category, product or service must be a string")
            try:
                self.category = logsource['category']
            except KeyError:
                self.category = None
            try:
                self.product = logsource['product']
            except KeyError:
                self.product = None
            try:
                self.service = logsource['service']
            except KeyError:
                self.service = None
            if self.category == None and self.product == None and self.service == None:
                raise SigmaConfigParseError("Log source definition will not match")

            if 'index' in logsource:
                index = logsource['index']
                if type(index) not in (str, list):
                    raise SigmaConfigParseError("Logsource index must be string or list of strings")
                if type(index) == list and not all([type(index) == str for index in logsource['index']]):
                    raise SigmaConfigParseError("Logsource index patterns must be strings")
                if type(index) == list:
                    self.index = index
                else:
                    self.index = [ index ]
            else:
                # no default index handling here - this branch is executed if log source definitions are parsed from
                # config and these must not necessarily contain an index definition. A valid index may later be result
                # from a merge, where default index handling applies.
                self.index = []

            if 'conditions' in logsource:
                if type(logsource['conditions']) != dict:
                    raise SigmaConfigParseError("Logsource conditions must be a map")
                cond = ConditionAND()
                for key, value in logsource['conditions'].items():
                    cond.add((key, value))
                self.conditions = cond
            else:
                self.conditions = None
        else:
            raise SigmaConfigParseError("Logsource definitions must be maps")

    def matches(self, category, product, service):
        """Match log source definition against given criteria, None = ignore"""
        searched = 0
        for searchval, selfval in zip((category, product, service), (self.category, self.product, self.service)):
            if searchval == None and selfval != None:
                return False
            if selfval != None:
                searched += 1
                if searchval != selfval:
                    return False
        if searched:
            return True

    def get_indexcond(self):
        """Get index condition if index field name is configured"""
        cond = ConditionOR()
        if self.indexfield:
            for index in self.index:
                cond.add((self.indexfield, index))
            return cond
        else:
            return None

    def __str__(self):
        return "[ LogSourceConfiguration: %s %s %s indices: %s ]" % (self.category, self.product, self.service, str(self.index))

class SigmaConfigParseError(Exception):
    pass

# Rule Filtering
class SigmaRuleFilter:
    """Filter for Sigma rules with conditions"""
    LEVELS = {
            "low"      : 0,
            "medium"   : 1,
            "high"     : 2,
            "critical" : 3
            }
    STATES = ["experimental", "testing", "stable"]

    def __init__(self, expr):
        self.minlevel   = None 
        self.maxlevel   = None 
        self.status     = None
        self.logsources = list()

        for cond in [c.replace(" ", "") for c in expr.split(",")]:
            if cond.startswith("level<="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.maxlevel = self.LEVELS[level]
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("level>="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.minlevel = self.LEVELS[level]
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("level="):
                try:
                    level = cond[cond.index("=") + 1:]
                    self.minlevel = self.LEVELS[level]
                    self.maxlevel = self.minlevel
                except KeyError as e:
                    raise SigmaRuleFilterParseException("Unknown level '%s' in condition '%s'" % (level, cond)) from e
            elif cond.startswith("status="):
                self.status = cond[cond.index("=") + 1:]
                if self.status not in self.STATES:
                    raise SigmaRuleFilterParseException("Unknown status '%s' in condition '%s'" % (self.status, cond))
            elif cond.startswith("logsource="):
                self.logsources.append(cond[cond.index("=") + 1:])
            else:
                raise SigmaRuleFilterParseException("Unknown condition '%s'" % cond)

    def match(self, yamldoc):
        """Match filter conditions against rule"""
        # Levels
        if self.minlevel is not None or self.maxlevel is not None:
            try:
                level = self.LEVELS[yamldoc['level']]
            except KeyError:    # missing or invalid level
                return False    # User wants level restriction, but it's not possible here

            # Minimum level
            if self.minlevel is not None:
                if level < self.minlevel:
                    return False
            # Maximum level
            if self.maxlevel is not None:
                if level > self.maxlevel:
                    return False

        # Status
        if self.status is not None:
            try:
                status = yamldoc['status']
            except KeyError:    # missing status
                return False    # User wants status restriction, but it's not possible here
            if status != self.status:
                return False

        # Log Sources
        if len(self.logsources) > 0:
            try:
                logsources = { value for key, value in yamldoc['logsource'].items() }
            except (KeyError, AttributeError):    # no log source set
                return False    # User wants status restriction, but it's not possible here

            for logsrc in self.logsources:
                if logsrc not in logsources:
                    return False

        # all tests passed
        return True

class SigmaRuleFilterParseException(Exception):
    pass
