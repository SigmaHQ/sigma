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
from sigma.config.mapping import FieldMapping, FieldMappingChain

# Chain of multiple configurations
class SigmaConfigurationChain(list):
    """
    Chain of SigmaConfiguration objects. Behaves like a list of Sigma configuration objects on the one side and
    like a SigmaConfiguration object on the other. All methods are applied to the given parameters in the order
    of addition of the configurations.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.backend = None
        self.defaultindex = None
        self.config = dict()
        self.fieldmappings = dict()
        self.logsources = dict()

        for config in self:
            self.postprocess_config(config)

    def append(self, config):
        super().append(config)
        self.postprocess_config(config)

    def postprocess_config(self, config):
        self.defaultindex = config.defaultindex
        self.config.update(config.config)
        self.fieldmappings.update(config.fieldmappings)
        self.logsources.update(config.logsources)

    def get_fieldmapping(self, fieldname):
        """Return mapped fieldname by iterative application of each config stored in configuration chain."""
        if self:
            fieldmappings = FieldMappingChain(fieldname)
            for config in self:
                fieldmappings.append(config)
            return fieldmappings
        else:
            return FieldMapping(fieldname)

    def get_logsource(self, category, product, service):
        """Return merged log source definition of all logosurces that match criteria across all Sigma conversion configurations in chain."""
        matching = list()
        for config in self:
            for logsource in config.logsources:
                if logsource.matches(category, product, service):
                    matching.append(logsource)
                    if logsource.rewrite is not None:
                        category, product, service = logsource.rewrite
        return SigmaLogsourceConfiguration(matching, self.defaultindex)

    def set_backend(self, backend):
        """Set backend for all sigma conversion configurations in chain."""
        self.backend = backend
        for config in self:
            config.set_backend(backend)

    def get_indexfield(self):
        """Get index condition if index field name is configured"""
        if self.backend is not None:
            return self.backend.index_field

# Configuration
class SigmaConfiguration:
    """Sigma converter configuration. Contains field mappings and logsource descriptions"""
    def __init__(self, configyaml=None):
        if configyaml == None:
            self.config = None
            self.order = None
            self.fieldmappings = dict()
            self.logsources = dict()
            self.defaultindex = None
            self.backend = None
        else:
            config = yaml.safe_load(configyaml)
            self.config = config

            self.fieldmappings = dict()
            try:
                for source, target in config['fieldmappings'].items():
                    self.fieldmappings[source] = FieldMapping(source, target)
            except TypeError as e:
                raise SigmaConfigParseError("Configuration has wrong type, should be map") from e
            except KeyError:
                pass

            if type(self.fieldmappings) != dict:
                raise SigmaConfigParseError("Fieldmappings must be a map")

            self.order = config.setdefault("order", None)
            self.defaultindex = config.setdefault('defaultindex', None)

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
                    self.logsources.append(SigmaLogsourceConfiguration(logsource, self.defaultindex))

    def get_indexfield(self):
        """Get index condition if index field name is configured"""
        if self.backend is not None:
            return self.backend.index_field

class SigmaLogsourceConfiguration:
    """Contains the definition of a log source"""
    def __init__(self, logsource=None, defaultindex=None):
        if logsource == None:               # create empty object
            self.merged = False
            self.category = None
            self.product = None
            self.service = None
            self.index = list()
            self.conditions = list()    # a list of (field, value) tuples which are OR-linked in the generated query. May also contain such a list as list element (in case of merged log sources)
            self.rewrite = None
        elif type(logsource) == list and all([isinstance(o, SigmaLogsourceConfiguration) for o in logsource]):      # list of SigmaLogsourceConfigurations: merge
            self.merged = True
            if any([ ls.merged for ls in logsource ]):      # Ensure that already merged objects are not merged again
                raise TypeError("Nested merging of SigmaLogsourceConfiguration objects is not allowed")
            rewrites = { ls.rewrite for ls in logsource if ls.rewrite is not None }
            if len(rewrites) > 1:
                raise ValueError("More than one matching log source contains a rewrite part")
            elif len(rewrites) == 1:
                self.rewrite = rewrites.pop()
            else:
                self.rewrite = None

            # Merge category, product and service
            categories = { ls.category for ls in logsource if ls.category is not None }
            products = { ls.product for ls in logsource if ls.product is not None }
            services = { ls.service for ls in logsource if ls.service is not None }
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

            self.conditions = [ ls.conditions for ls in logsource if ls.conditions ]        # build list of list of (field, value) tuples as base for merged query condition.
        elif type(logsource) == dict:       # create logsource configuration from parsed yaml
            self.merged = False
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

            try:
                if type(logsource['rewrite']) is not dict:
                    raise SigmaConfigParseError("Rewrite rule must be a map")
                rewrite = logsource['rewrite']
                if not { 'category', 'product', 'service' }.issuperset(rewrite.keys()):
                    raise SigmaConfigParseError("Rewrite rule in log source configuration may only contain the keys 'category', 'product' and 'service'")
                if { str } != { type(value) for value in rewrite.values() }:
                    raise SigmaConfigParseError("Rewrite rule values may only contain strings")
                self.rewrite = tuple((rewrite.get(key) for key in ( 'category', 'product', 'service' )))    # build a (category, product, service) tuple from dict
            except KeyError:
                self.rewrite = None

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

            try:
                if type(logsource['conditions']) != dict:
                    raise SigmaConfigParseError("Logsource conditions must be a map")
                self.conditions = [ (field, value) for field, value in logsource['conditions'].items() ]    # build list of (field, value) tuples as base for query condition
            except KeyError:
                self.conditions = list()
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

    def __str__(self):  # pragma: no cover
        return "[ LogSourceConfiguration: %s %s %s indices: %s ]" % (self.category, self.product, self.service, str(self.index))
