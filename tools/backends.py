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
        return "%s:%s" % (key, self.generateNode(value))

    def generateValueNode(self, node):
        return "\"%s\"" % (self.cleanValue(str(node)))

class ElasticsearchDSLBackend(BaseBackend):
    """Converts Sigma rule into Elasticsearch DSL query (JSON)."""
    identifier = "es-dsl"
    active = True

class KibanaBackend(ElasticsearchDSLBackend):
    """Converts Sigma rule into Kibana JSON Configurations."""
    identifier = "kibana"
    active = True

class SplunkBackend(BaseBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "splunk"
    active = True

class NullBackend(BaseBackend):
    """Does nothing, for debugging purposes."""
    identifier = "null"
    active = True

    def generate(self, parsed):
        pass
