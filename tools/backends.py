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
        return self.generateNode(parsed.getParseTree())

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

class ElasticsearchQuerystringBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True
    reEscape = re.compile("([+\\-=!(){}\\[\\]^\"~:\\\\/]|&&|\\|\\|)")
    reClear = re.compile("[<>]")

    def cleanValue(self, val):
        val = self.reEscape.sub("\\\\\g<1>", val)
        return self.reClear.sub("", val)

    def generateANDNode(self, node):
        return " AND ".join([self.generateNode(val) for val in node])

    def generateORNode(self, node):
        return " OR ".join([self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return "NOT " + self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return "(%s)" % self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(%s)" % (" ".join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        return "%s:%s" % (self.sigmaconfig.get_fieldmapping(key), self.generateNode(value))

    def generateValueNode(self, node):
        return "\"%s\"" % (self.cleanValue(str(node)))

class ElasticsearchDSLBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch DSL query (JSON)."""
    identifier = "es-dsl"
    active = False

class KibanaBackend(ElasticsearchDSLBackend):
    """Converts Sigma rule into Kibana JSON Configurations."""
    identifier = "kibana"
    active = False

class LogPointBackend(BaseBackend):
    """Converts Sigma rule into LogPoint query"""
    identifier = "logpoint"
    active = True
    reEscape = re.compile('(["\\\\])')

    def cleanValue(self, val):
        return self.reEscape.sub("\\\\\g<1>", val)
    
    def generateANDNode(self, node):
        return " ".join([self.generateNode(val) for val in node])
    
    def generateORNode(self, node):
        return " OR ".join([self.generateNode(val) for val in node])
    
    def generateNOTNode(self, node):
        return " -" + self.generateNode(node.item)
        
    def generateSubexpressionNode(self, node):
        return "(%s)" % self.generateNode(node.items)
        
    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "[%s]" % (", ".join([self.generateNode(value) for value in node]))
    
    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        if type(value) == list:
            return "%s IN %s" % (self.sigmaconfig.get_fieldmapping(key), self.generateNode(value))
        return "%s=%s" % (self.sigmaconfig.get_fieldmapping(key), self.generateNode(value))
        
    def generateValueNode(self, node):
        return "\"%s\"" % (self.cleanValue(str(node)))
    
class SplunkBackend(BaseBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "splunk"
    active = True
    index_field = "index"
    reEscape = re.compile('(["\\\\])')

    def cleanValue(self, val):
        return self.reEscape.sub("\\\\\g<1>", val)

    def generateANDNode(self, node):
        return " ".join([self.generateNode(val) for val in node])

    def generateORNode(self, node):
        return " OR ".join([self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return "NOT " + self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return "(%s)" % self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(%s)" % (" ".join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) in (str, int):
            return '%s=%s' % (self.sigmaconfig.get_fieldmapping(key), self.generateNode(value))
        elif type(value) == list:
            return "(" + (" OR ".join(['%s=%s' % (self.sigmaconfig.get_fieldmapping(key), self.generateValueNode(item)) for item in value])) + ")"
        else:
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))

    def generateValueNode(self, node):
        return "\"%s\"" % (self.cleanValue(str(node)))

class FieldnameListBackend(BaseBackend):
    """List all fieldnames from given Sigma rules for creation of a field mapping configuration."""
    identifier = "fieldlist"
    active = True

    def generate(self, parsed):
        return "\n".join(sorted(set(list(flatten(self.generateNode(parsed.getParseTree()))))))

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
        return [self.sigmaconfig.get_fieldmapping(key)]

    def generateValueNode(self, node):
        return []

# Helpers
def flatten(l):
  for i in l:
      if type(i) == list:
          yield from flatten(i)
      else:
          yield i
