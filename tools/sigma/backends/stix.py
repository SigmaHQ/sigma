import sigma
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend


class STIXBackend(SingleTextQueryBackend):
    """Converts Sigma rule into STIX pattern."""
    identifier = "stix"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    valueExpression = "\'%s\'"
    mapExpression = "%s = %s"
    mapListsSpecialHandling = True
    sigmaSTIXObjectName = "x-sigma"

    def cleanKey(self, key):
        if key is None:
            raise TypeError("Backend does not support empty key " + str(key))
        else:
            return key

    def cleanValue(self, value):
        return value

    def generateMapItemListNode(self, key, value):
        items_list = list()
        for item in value:
            if type(item) == str and "*" in item:
                item = item.replace("*", "%")
                items_list.append('%s LIKE %s' % (self.cleanKey(key), self.generateValueNode(item)))
            else:
                items_list.append('%s = %s' % (self.cleanKey(key), self.generateValueNode(item)))
        return '('+" OR ".join(items_list)+')'

    def generateMapItemTypedNode(self, key, value):
        if type(value) == SigmaRegularExpressionModifier:
            regex = str(value)
            # Regular Expressions have to match the full value in QRadar
            if not (regex.startswith('^') or regex.startswith('.*')):
                regex = '.*' + regex
            if not (regex.endswith('$') or regex.endswith('.*')):
                regex = regex + '.*'
            return "%s MATCHES %s" % (self.cleanKey(key), self.generateValueNode(regex))
        else:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(value.identifier))

    def generateMapItemNode(self, node):
        key, value = node
        if ":" not in key:
            key = "%s:%s" % (self.sigmaSTIXObjectName, str(key).lower())
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                return "%s LIKE %s" % (self.cleanKey(key), self.generateValueNode(value))
            elif type(value) in (str, int):
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            return "[" + query + "]"

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        return result
