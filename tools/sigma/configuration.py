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
from sigma.parser.condition import ConditionAND, ConditionOR
from sigma.config.exceptions import SigmaConfigParseError
from sigma.config.mapping import FieldMapping

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
