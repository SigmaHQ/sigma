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

import sigma
from .mixins import RulenameCommentMixin, QuoteCharMixin

class BackendOptions(dict):
    """Object contains all options that should be passed to the backend from command line (or other user interfaces)"""

    def __init__(self, options):
        """
        Receives the argparser result from the backend option paramater value list (nargs=*) and builds the dict from it. There are two option types:

        * key=value: self{key} = value
        * key: self{key} = True
        """
        if options == None:
            return
        for option in options:
            parsed = option.split("=", 1)
            try:
                self[parsed[0]] = parsed[1]
            except IndexError:
                self[parsed[0]] = True

### Generic backend base classes
class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False
    index_field = None    # field name that is used to address indices
    file_list = None
    options = tuple()     # a list of tuples with following elements: option name, default value, help text, target attribute name (option name if None)

    def __init__(self, sigmaconfig, backend_options=None):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it.
        """
        super().__init__()
        if not isinstance(sigmaconfig, (sigma.configuration.SigmaConfiguration, None)):
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

    def dumpNode(self, node, indent=''):
        """
        Recursively print the AST rooted at *node* for debugging.
        """
        import sys
        if hasattr(node, 'items'):
            print("%s%s<%s>" % (indent, type(node).__name__,
                                type(node.items).__name__), file=sys.stderr)
            if type(node.items) != list:
                self.dumpNode(node.items, indent + '  ')
            else:
                for item in node.items:
                    self.dumpNode(item, indent + '  ')
        else:
            print("%s%s=%s" % (indent, type(node).__name__,
                                       repr(node)), file=sys.stderr)
        return node

    def stripSubexpressionNode(self, node):
        """
        Recursively strips all subexpressions (i.e. brackets) from the AST.
        """
        if type(node) == sigma.parser.condition.NodeSubexpression:
            assert(type(node.items) != list)
            return self.stripSubexpressionNode(node.items)
        if hasattr(node, 'items'):
            node.items = list(map(self.stripSubexpressionNode, node.items))
        return node

    def unstripSubexpressionNode(self, node):
        """
        Recursively adds brackets around AND and OR operations in the AST.
        """
        if type(node) in (sigma.parser.condition.ConditionAND,
                          sigma.parser.condition.ConditionOR,
                          sigma.parser.condition.ConditionNOT):
            newnode = sigma.parser.condition.NodeSubexpression(node)
            node.items = list(map(self.unstripSubexpressionNode, node.items))
            return newnode
        return node

    def optimizeNode(self, node, changes=False):
        """
        Recursively optimize the AST rooted at *node* once.  Returns the new
        root node and a boolean indicating if the tree was changed in this
        invocation or any of the sub-invocations.

        You MUST remove all subexpression nodes from the AST before calling
        this function.  Subexpressions are implicit around AND/OR/NOT nodes.
        """
        def fast_ordered_uniq(l):
            seen = set()
            return [x for x in node.items if x not in seen and not seen.add(x)]

        if type(node) in (sigma.parser.condition.ConditionOR,
                          sigma.parser.condition.ConditionAND):
            # Remove empty OR(X), AND(X)
            if len(node.items) == 0:
                return None, True

            # OR(X), AND(X)                 =>  X
            if len(node.items) == 1:
                return self.optimizeNode(node.items[0], changes=True)

            # OR(X, X, ...), AND(X, X, ...) =>  OR(X, ...), AND(X, ...)
            uniq_items = fast_ordered_uniq(node.items)
            if len(uniq_items) < len(node.items):
                node.items = uniq_items
                return self.optimizeNode(node, changes=True)

            # OR(X, OR(Y))                  =>  OR(X, Y)
            if any(type(child) == type(node) for child in node.items) and \
               all(type(child) in (type(node), tuple) for child in node.items):
                newitems = []
                for child in node.items:
                    if hasattr(child, 'items'):
                        newitems.extend(child.items)
                    else:
                        newitems.append(child)
                node.items = newitems
                return self.optimizeNode(node, changes=True)

            # OR(AND(X, ...), AND(X, ...))  =>  AND(X, OR(AND(...), AND(...)))
            if type(node) == sigma.parser.condition.ConditionOR:
                othertype = sigma.parser.condition.ConditionAND
            else:
                othertype = sigma.parser.condition.ConditionOR
            if all(type(child) == othertype for child in node.items):
                promoted = []
                for cand in node.items[0]:
                    if all(cand in child for child in node.items[1:]):
                        promoted.append(cand)
                if len(promoted) > 0:
                    for child in node.items:
                        for cand in promoted:
                            child.items.remove(cand)
                    newnode = othertype()
                    newnode.items = promoted
                    newnode.add(node)
                    return self.optimizeNode(newnode, changes=True)
            # fallthrough
        elif type(node) == sigma.parser.condition.ConditionNOT:
            # NOT(NOT(X))                   =>  X
            assert(len(node.items) == 1)
            if type(node.items[0]) == sigma.parser.condition.ConditionNOT:
                assert(len(node.items[0].items) == 1)
                return self.optimizeNode(node.items[0].items[0], changes=True)
            # fallthrough
        else:
            return node, changes

        itemresults = [self.optimizeNode(item, changes) for item in node.items]
        node.items = [res[0] for res in itemresults]
        if any(res[1] for res in itemresults):
            changes = True
        return node, changes

    def optimizeTree(self, tree):
        """
        Optimize the boolean expressions in the AST rooted at *node*.

        The main idea behind optimizing the AST is that less repeated terms is
        generally better for backend performance.  This is especially relevant
        to backends that do not perform any query language optimization down
        the road, such as those that generate code.

        The following optimizations are currently performed:
        -   Removal of empty OR(), AND()
        -   OR(X), AND(X)                 =>  X
        -   OR(X, X, ...), AND(X, X, ...) =>  OR(X, ...), AND(X, ...)
        -   OR(X, OR(Y))                  =>  OR(X, Y)
        -   OR(AND(X, ...), AND(X, ...))  =>  AND(X, OR(AND(...), AND(...)))
        -   NOT(NOT(X))                   =>  X

        A common example for when these suboptimal rules actually occur in
        practice is when a rule has multiple alternative detections that are
        OR'ed together in the condition, and all of the detections include a
        common element, such as the same EventID.

        This implementation is not optimized for performance and will perform
        poorly on very large expressions.
        """
        #self.dumpNode(tree)
        tree = self.stripSubexpressionNode(tree)
        #self.dumpNode(tree)
        changes = True
        while changes:
            tree, changes = self.optimizeNode(tree)
        #self.dumpNode(tree)
        tree = self.unstripSubexpressionNode(tree)
        #self.dumpNode(tree)
        return tree

    def generateQuery(self, parsed):
        result = self.generateNode(self.optimizeTree(parsed.parsedSearch))
        if parsed.parsedAgg:
            result += self.generateAggregation(parsed.parsedAgg)
        return result

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        elif type(node) in (str, int):
            return self.generateValueNode(node)
        elif type(node) == list:
            return self.generateListNode(node)
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
    nullExpression = None               # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = None            # Expression of queries for not null values. %s is field name
    mapExpression = None                # Syntax for field/value conditions. First %s is key, second is value
    mapListsSpecialHandling = False     # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = None       # Syntax for field/value condititons where map value is a list

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
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
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return self.mapListValueExpression % (key, self.generateNode(value))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)
