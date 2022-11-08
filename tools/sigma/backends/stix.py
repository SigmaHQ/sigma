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
    notMapExpression = "%s != %s"
    mapListsSpecialHandling = True
    sort_condition_lists = True

    def cleanKey(self, key):
        if key is None:
            raise TypeError("Backend does not support empty key " + str(key))
        else:
            return key

    def cleanValue(self, value):
        return value

    def generateANDNode(self, node, currently_within_NOT_node=False):
        generated = [self.generateNode(val, currently_within_NOT_node) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node, currently_within_NOT_node=False):
        generated = [self.generateNode(val, currently_within_NOT_node) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node, currently_within_NOT_node=False):
        currently_within_NOT_node = not(currently_within_NOT_node)
        generated = self.generateNode(node.item, currently_within_NOT_node)
        if generated is not None:
            return generated
        else:
            return None

    def generateSubexpressionNode(self, node, currently_within_NOT_node=False):
        generated = self.generateNode(node.items, currently_within_NOT_node)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateMapItemNode(self, node, currently_within_NOT_node=False):
        fieldname, value = node

        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if currently_within_NOT_node:
                return self.notMapExpression % (transformed_fieldname, self.generateNode(value))
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value, currently_within_NOT_node)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value, currently_within_NOT_node=False):
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

    def generateMapItemNode(self, node, currently_within_NOT_node=False):
        key, value = node
        if ":" not in key:
            # key wasn't mapped
            return None
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if type(value) == str and "*" in value:
                value = value.replace("*", "%")
                if currently_within_NOT_node:
                    return "%s NOT LIKE %s" % (self.cleanKey(key), self.generateValueNode(value))
                return "%s LIKE %s" % (self.cleanKey(key), self.generateValueNode(value))
            elif type(value) in (str, int):
                if currently_within_NOT_node:
                    return self.notMapExpression % (self.cleanKey(key), self.generateValueNode(value))
                return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value, currently_within_NOT_node)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateValueNode(self, node, keypresent=True):
        if keypresent == False:
            if type(node) == str and "*" in node:
                node = node.replace("*", "%")
            return "artifact:payload_bin LIKE \'{0}\'".format(self.cleanValue(str(node)))
        else:
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
        elif type(node) in (str, int):
            return self.generateValueNode(node, keypresent=False)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            return "[" + query + "]"

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        return result
