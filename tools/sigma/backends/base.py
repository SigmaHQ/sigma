# Output backends for sigmac
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

import sys

import sigma
import yaml
import re

from sigma.backends.exceptions import NotSupportedError
from .mixins import RulenameCommentMixin, QuoteCharMixin
from sigma.parser.modifiers.base import SigmaTypeModifier

class BackendOptions(dict):
    """
    Object containing all the options that should be passed to the backend.

    The options can come from command line and a YAML configuration file, and will be merged together.
    Options from the command line take precedence.
    """

    def __init__(self, options, config_file):
        """
        :param options: unparsed options coming from the CLI
        :param config_file: path to a YAML configuration file
        """

        self._load_config_file(config_file)
        self._parse_options(options)

    def _parse_options(self, options):
        """
        Populates options from the unparsed options of the CLI

        :param options: list unparsed options from the CLI.
            Each option can have one of the following formats:
            - "key=value": the option key:value will be passed to the backend
            - "key": the option key:True will be passed to the backend
        """

        if options is None:
            return

        for option in options:
            parsed = option.split("=", 1)
            try:
                self[parsed[0]] = parsed[1]
            except IndexError:
                # If the option is present but doesn't map to a value, treat it as a boolean flag
                self[parsed[0]] = True

    def _load_config_file(self, path):
        """
        Populates options from a configuration file

        :param path: Path to the configuration file
        """
        if path is None:
            return

        try:
            with open(path, 'r') as config_file:
                backend_config = yaml.safe_load(config_file.read())
                self.update(backend_config)
        except (IOError, OSError) as e:
            print("Failed to open backend configuration file '%s': %s" % (path, str(e)), file=sys.stderr)
            exit(1)
        except yaml.YAMLError as e:
            print("Failed to parse backend configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            exit(1)

### Generic backend base classes
class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False
    index_field = None    # field name that is used to address indices
    file_list = None
    options = tuple()     # a list of tuples with following elements: option name, default value, help text, target attribute name (option name if None)
    config_required = True
    default_config = None
    mapExpression = ""

    def __init__(self, sigmaconfig, backend_options=dict()):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it.
        """
        super().__init__()
        if not isinstance(sigmaconfig, (sigma.configuration.SigmaConfiguration, sigma.configuration.SigmaConfigurationChain, None)):
            raise TypeError("SigmaConfiguration object expected")
        self.backend_options = backend_options
        self.sigmaconfig = sigmaconfig
        self.sigmaconfig.set_backend(self)

        # Parse options
        for option, default_value, _, target in self.options:
            if target is None:
                target = option
            setattr(self, target, self.backend_options.setdefault(option, default_value))

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        if len(sigmaparser.condparsed) > 1:
            raise NotImplementedError("Base backend doesn't support multiple conditions")
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            return result

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            result += self.generateAggregation(parsed.parsedAgg)
        #result = self.applyOverrides(result)
        return result

    def applyOverrides(self, query):
        try:
            if 'overrides' in self.sigmaconfig.config and isinstance(query, str):
                for expression in self.sigmaconfig.config['overrides']:
                    if 'regexes' in expression:
                        for x in expression['regexes']:
                            sub = expression['field']
                            value = expression['value']
                            query = re.sub(x, self.mapExpression % (sub, value), query)
                    if 'literals' in expression:
                        for x in expression['literals']:
                            sub = expression['field']
                            value = expression['value']
                            query = query.replace(x, self.mapExpression % (sub, value))
        except Exception:
            pass
        return query

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.applyOverrides(self.generateANDNode(node))
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.applyOverrides(self.generateORNode(node))
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.applyOverrides(self.generateNOTNode(node))
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.applyOverrides(self.generateNULLValueNode(node))
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.applyOverrides(self.generateNotNULLValueNode(node))
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.applyOverrides(self.generateSubexpressionNode(node))
        elif type(node) == tuple:
            return self.applyOverrides(self.generateMapItemNode(node))
        elif type(node) in (str, int):
            return self.applyOverrides(self.generateValueNode(node))
        elif type(node) == list:
            return self.applyOverrides(self.generateListNode(node))
        elif isinstance(node, SigmaTypeModifier):
            return self.applyOverrides(self.generateTypedValueNode(node))
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generateANDNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateORNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateNOTNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateSubexpressionNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateListNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateMapItemNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateTypedValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateNULLValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateNotNULLValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateAggregation(self, agg):
        raise NotImplementedError("Aggregations not implemented for this backend")

    def generateBefore(self, parsed):
        return ""

    def generateAfter(self, parsed):
        return ""

    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        pass

class SingleTextQueryBackend(RulenameCommentMixin, BaseBackend, QuoteCharMixin):
    """Base class for backends that generate one text-based expression from a Sigma rule"""
    identifier = "base-textquery"
    active = False

    # the following class variables define the generation and behavior of queries from a parse tree some are prefilled with default values that are quite usual
    andToken = None                     # Token used for linking expressions with logical AND
    orToken = None                      # Same for OR
    notToken = None                     # Same for NOT
    subExpression = None                # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = None               # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = None                # Character for separation of list items
    valueExpression = None              # Expression of values, %s represents value
    typedValueExpression = dict()       # Expression of typed values generated by type modifiers. modifier identifier -> expression dict, %s represents value
    nullExpression = None               # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = None            # Expression of queries for not null values. %s is field name
    mapExpression = None                # Syntax for field/value conditions. First %s is fieldname, second is value
    mapListsSpecialHandling = False     # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = None       # Syntax for field/value condititons where map value is a list

    sort_condition_lists = False        # Sort condition items for AND and OR conditions

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return self.notToken + generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if len(node.items) == 1:
            # A sub expression with length 1 is not a proper sub expression, no self.subExpression required
            return generated
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        result = [self.generateNode(value) for value in node]
        if len(result) == 1:
            # A list with length 1 is not a proper list, no self.listExpression required
            return result[0]
        return self.listExpression % (self.listSeparator.join(result))

    def generateMapItemNode(self, node):
        fieldname, value = node

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

    def generateMapItemListNode(self, fieldname, value):
        return self.mapListValueExpression % (fieldname, self.generateNode(value))

    def generateMapItemTypedNode(self, fieldname, value):
        return self.mapExpression % (fieldname, self.generateTypedValueNode(value))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateTypedValueNode(self, node):
        try:
            return self.typedValueExpression[type(node)] % (str(node))
        except KeyError:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(node.identifier))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        """
        return fieldname
