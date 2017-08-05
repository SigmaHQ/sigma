# Output backends for sigmac

import json
import re
import sigma

def getBackendList():
    """Return list of backend classes"""
    return list(filter(lambda cls: type(cls) == type and issubclass(cls, BaseBackend) and cls.active, [item[1] for item in globals().items()]))

def getBackendDict():
    return {cls.identifier: cls for cls in getBackendList() }

def getBackend(name):
    try:
        return getBackendDict()[name]
    except KeyError as e:
        raise LookupError("Backend not found") from e

### Generic base classes

class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False
    index_field = None      # field name that is used to address indices

    def __init__(self, sigmaconfig):
        if not isinstance(sigmaconfig, (sigma.SigmaConfiguration, None)):
            raise TypeError("SigmaConfiguration object expected")
        self.sigmaconfig = sigmaconfig
        self.sigmaconfig.set_backend(self)

    def generate(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            result += self.generateAggregation(parsed.parsedAgg)
        return result

    def generateNode(self, node):
        if type(node) == sigma.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.NodeSubexpression:
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

    def generateAggregation(self, agg):
        raise NotImplementedError("Aggregations not implemented for this backend")

class SingleTextQueryBackend(BaseBackend):
    """Base class for backends that generate one text-based expression from a Sigma rule"""
    identifier = "base-textquery"
    active = False

    # the following class variables define the generation and behavior of queries from a parse tree some are prefilled with default values that are quite usual
    reEscape = None                     # match characters that must be quoted
    escapeSubst = "\\\\\g<1>"           # Substitution that is applied to characters/strings matched for escaping by reEscape
    reClear = None                      # match characters that are cleaned out completely
    andToken = None                     # Token used for linking expressions with logical AND
    orToken = None                      # Same for OR
    notToken = None                     # Same for NOT
    subExpression = None                # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = None               # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = None                # Character for separation of list items
    valueExpression = None              # Expression of values, %s represents value
    mapExpression = None                # Syntax for field/value conditions. First %s is key, second is value
    mapListsSpecialHandling = False     # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = None       # Syntax for field/value condititons where map value is a list

    def cleanValue(self, val):
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        if self.reClear:
            val = self.reClear.sub("", val)
        return val

    def generateANDNode(self, node):
        return self.andToken.join([self.generateNode(val) for val in node])

    def generateORNode(self, node):
        return self.orToken.join([self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return self.notToken + self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

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

### Backends for specific SIEMs

class ElasticsearchQuerystringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([+\\-=!(){}\\[\\]^\"~:\\\\/]|&&|\\|\\|)")
    reClear = re.compile("[<>]")
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    mapExpression = "%s:%s"
    mapListsSpecialHandling = False

class ElasticsearchDSLBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch DSL query (JSON)."""
    identifier = "es-dsl"
    active = False

class KibanaBackend(ElasticsearchDSLBackend):
    """Converts Sigma rule into Kibana JSON Configurations."""
    identifier = "kibana"
    active = False

class LogPointBackend(SingleTextQueryBackend):
    """Converts Sigma rule into LogPoint query"""
    identifier = "logpoint"
    active = True

    reEscape = re.compile('(["\\\\])')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = " -"
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ", "
    valueExpression = "\"%s\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    
    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | chart %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | chart %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)
    
class SplunkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "splunk"
    active = True
    index_field = "index"

    reEscape = re.compile('(["\\\\])')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = False
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, node):
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | stats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | stats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)

### Backends for developement purposes

class FieldnameListBackend(BaseBackend):
    """List all fieldnames from given Sigma rules for creation of a field mapping configuration."""
    identifier = "fieldlist"
    active = True

    def generate(self, parsed):
        return "\n".join(sorted(set(list(flatten(self.generateNode(parsed.parsedSearch))))))

    def generateANDNode(self, node):
        return [self.generateNode(val) for val in node]

    def generateORNode(self, node):
        return self.generateANDNode(node)

    def generateNOTNode(self, node):
        return self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return [self.generateNode(value) for value in node]

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        return [key]

    def generateValueNode(self, node):
        return []

# Helpers
def flatten(l):
  for i in l:
      if type(i) == list:
          yield from flatten(i)
      else:
          yield i
