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

    def generateMapItemListNode(self, key, value, currently_within_NOT_node):
        items_list = list()
        for item in value:
            if type(item) == str and "*" in item:
                item = item.replace("*", "%")
                if currently_within_NOT_node:
                    items_list.append('%s NOT LIKE %s' % (self.cleanKey(key), self.generateValueNode(item)))
                else:
                    items_list.append('%s LIKE %s' % (self.cleanKey(key), self.generateValueNode(item)))
            else:
                if currently_within_NOT_node:
                    items_list.append('%s != %s' % (self.cleanKey(key), self.generateValueNode(item)))
                else:
                    items_list.append('%s = %s' % (self.cleanKey(key), self.generateValueNode(item)))
        if currently_within_NOT_node:
            return '(' + " AND ".join(items_list) + ')'
        else:
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

    def generateMapItemNode(self, node, currently_within_NOT_node):
        key, value = node
        if ":" not in key:
            key = "%s:%s" % (self.sigmaSTIXObjectName, str(key).lower())
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                if currently_within_NOT_node:
                    return "%s NOT LIKE %s" % (self.cleanKey(key), self.generateValueNode(value))
                return "%s LIKE %s" % (self.cleanKey(key), self.generateValueNode(value))
            elif type(value) in (str, int):
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value, currently_within_NOT_node)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNode(self, node, currently_within_NOT_node=False):
        if type(node) == sigma.parser.condition.ConditionAND:
            if currently_within_NOT_node:
                return self.generateORNode(node, currently_within_NOT_node)
            return self.generateANDNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            if currently_within_NOT_node:
                return self.generateANDNode(node, currently_within_NOT_node)
            return self.generateORNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node, currently_within_NOT_node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node, currently_within_NOT_node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node, currently_within_NOT_node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            return "[" + query + "]"

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        return result
