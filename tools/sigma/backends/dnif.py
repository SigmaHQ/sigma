# Output backends for sigmac
# Copyright 2022 Netmonastery, Inc.#

import re
from .base import SingleTextQueryBackend
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.parser.condition import SigmaAggregationParser


class DnifBackend(SingleTextQueryBackend):
    """Base class for DNIF backend"""
    identifier = "dnif"
    andToken = " and "
    orToken = " or "
    notToken = "not"
    subExpression = "%s"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "\"%s\""
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s == \"%s\""
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    active = True

    config_required = True
    ymlFileName = None

    def __init__(self, sigmaconfig, options=None):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified
        about the used backend class by
        passing the object instance to it.
        """
        super().__init__(sigmaconfig)
        self.table = None
        self.timeframe = None

    def generateANDNode(self, node):
        """
        Generates and nodes for query
        this method accepts the node and returns transformed node
        according to the query language
        """
        generated = [self.generateNode(val) for val in node]
        transformed = []
        for generated_node in generated:
            if generated_node is not None:
                if re.search(self.orToken, generated_node):
                    transformed.append("(" + generated_node + ")")
                else:
                    transformed.append(generated_node)
        return self.andToken.join(transformed)

    def default_value_mapping(self, val):
        """
        creates default value mapping for
        the rules. this method accepts any value
        and returns a transformed value
        """
        if isinstance(val, int):
            return f"== {val}"
        default_operator = "=="
        if isinstance(val, str) and val[1:-1]:
            if "*" in val[1:-1]:  # value contains * inside string - use regex match
                default_operator = ""
                val = re.sub(r'(\\\\\*|\*)', '.*', val)
                if "\\" in val:
                    val = f'@rlike("%", "{val}")'
                else:
                    val = f'rlike("%", "{val}")'
                return f'{default_operator} {self.cleanValue(val)}'
            elif val.startswith("*") or val.endswith("*"):
                default_operator = "like"
                if val.startswith("*") and val.endswith("*"):
                    val = f'%{val[1:-1]}%'
                elif val.startswith("*"):
                    val = f'%{val[1:]}'
                elif val.endswith("*"):
                    val = f'{val[:-1]}%'
                if "\\" in val:
                    return f'{default_operator} "{self.cleanValue(val)}"'
                return f'{default_operator} "{self.cleanValue(val)}"'
            elif "\\" in val:
                return f'{default_operator} @"{self.cleanValue(val)}"'
        elif isinstance(val, SigmaRegularExpressionModifier):
            default_operator = ""
            val = f'rlike("%", "{val}")'
            return f'{default_operator} {self.cleanValue(val)}'
        return f'{default_operator} "{self.cleanValue(val)}"'

    def generateORNode(self, node):
        """
        Generates or nodes for query
        this method accepts the node and returns transformed node
        according to the query language
        """
        generated = [self.generateNode(val) for val in node]
        transformed = {}
        transformed_query = []
        for generated_node in generated:
            if generated_node is not None:
                generated_node = generated_node.split(' == ')
                if len(generated_node) == 1:
                    transformed_query.append(generated_node[0])
                else:
                    if generated_node[0] not in transformed:
                        transformed[generated_node[0]] = [generated_node[1]]
                    else:
                        if generated_node[1] not in transformed[generated_node[0]]:
                            transformed[generated_node[0]].append(generated_node[1])
        if transformed:
            _transformed_query = [f'{key} IN ({", ".join(value)})'
                                  for key, value in transformed.items()]
            transformed_query.extend(_transformed_query)
        return self.orToken.join(transformed_query)

    def generateAggregation(self, agg):
        """
        Generates aggregations for query
        this method accepts the aggregation and
        returns a query with aggregation applied to it
        according to the query language
        """
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented"+
                                      "for this backend")

        if agg.groupfield is None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield is None:
                    if agg.condition:
                        if self.timeframe:
                            return f" | select count(*) as count_col" \
                                   f" | having count_col {agg.cond_op} {agg.condition}" \
                                   f" | duration {self.timeframe}"
                        return f" | select count(*) as count_col" \
                               f" | having count_col {agg.cond_op} {agg.condition}"
                else:
                    if self.timeframe:
                        return f" | groupby {agg.groupfield}" \
                               f" | select {agg.groupfield}, count(*) as count_col" \
                               f" | having count_col {agg.cond_op} {agg.condition}" \
                               f" | duration {self.timeframe}"
                    return f" | groupby {agg.groupfield}" \
                           f" | select {agg.groupfield}, count(*) as count_col" \
                           f" | having count_col {agg.cond_op} {agg.condition}"
            if self.timeframe:
                return f' | groupby {agg.aggfield or ""}' \
                       f' | select {agg.aggfield or ""}, distinct_count({agg.aggfield or ""}), count(*) as total_count' \
                       f' | duration {self.timeframe}'

            return " | groupby %s" \
                   " | select %s, distinct_count(%s), count(*) " \
                   " as total_count" % (agg.aggfield or "",
                                        agg.aggfield or "",
                                        agg.aggfield or "")

        if agg.aggfunc_notrans == 'count':
            if agg.aggfield is None:
                if agg.condition:
                    if self.timeframe:
                        return " | groupby %s" \
                               " | select %s, count(*) as count_col" \
                               " | having count_col %s %s" \
                               " | duration %s" % (agg.groupfield,
                                                   agg.groupfield,
                                                   agg.cond_op,
                                                   agg.condition,
                                                   self.timeframe)
                    return " | groupby %s" \
                           " | select %s, count(*) as count_col" \
                           " | having count_col %s %s" % (agg.groupfield,
                                                          agg.groupfield,
                                                          agg.cond_op,
                                                          agg.condition)
            if self.timeframe:
                return " | groupby %s" \
                       " | select %s, count(%s)" \
                       " | duration %s" % (agg.groupfield or "",
                                           agg.groupfield or "",
                                           agg.aggfield or "",
                                           self.timeframe)
            return " | groupby %s" \
                   " | select %s, count(%s)" % (agg.groupfield or "",
                                                agg.groupfield or "",
                                                agg.aggfield or "")
        elif agg.aggfunc_notrans == 'sum':
            if agg.aggfield is None:
                if self.timeframe:
                    return " | groupby %s" \
                           " | select %s, sum(*) as count_col" \
                           " | having count_col %s %s" \
                           " | duration %s" % (agg.groupfield,
                                               agg.groupfield,
                                               agg.cond_op,
                                               agg.condition,
                                               self.timeframe)
                return " | groupby %s" \
                       " | select %s, sum(*) as count_col" \
                       " | having count_col %s %s" % (agg.groupfield,
                                                      agg.groupfield,
                                                      agg.cond_op,
                                                      agg.condition)
            else:
                if self.timeframe:
                    return " | groupby %s" \
                           " | select %s, sum(%s)" \
                           " | duration %s" % (agg.groupfield or "",
                                               agg.groupfield or "",
                                               agg.aggfield or "",
                                               self.timeframe)
                return " | groupby %s" \
                       " | select %s, sum(%s)" % (agg.groupfield or "",
                                                  agg.groupfield or "",
                                                  agg.aggfield or "")

    def generateMapItemNode(self, node):
        key, value = node
        key = self.fieldNameMapping(key, value)
        # handle map items with values list like multiple OR-chained conditions
        if type(value) == list:
            return self.generateORNode(
                    [(key, v) for v in value]
                    )
        elif type(value) in (str, int) or isinstance(value, SigmaRegularExpressionModifier):    # default value processing'
            value_mapping = self.default_value_mapping
            mapping = (key, value_mapping)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, self.cleanValue(value))]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                # iterate mapping and mapping source value synchronously over key and value
                for mapitem, val in zip(mapping, node):
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        mapitem_value = mapitem(self.cleanValue(val))
                        if 'rlike' in mapitem_value:
                            mapitem_value = re.sub(r'\"%\"', result[0], mapitem_value)
                        result.append(mapitem_value)
                for res in result:
                    if 'rlike' in res:
                        result[0] = ''
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            return super().generateMapItemNode(node)

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return "%s %s" % (self.notToken, generated)
        else:
            return None

    def generateMapItemListNode(self, key, value):
        if isinstance(value, SigmaRegularExpressionModifier):
            key_mapped = self.fieldNameMapping(key, value)
            return {'regexp': {key_mapped: str(value)}}
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        if isinstance(value, list):
            if 'or' in value:
                self.generateORNode(value)
            elif 'and' in value:
                self.generateANDNode(value)
        return ' or '.join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])

    def generateTypedValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateNULLValueNode(self, fieldname):
        return self.nullExpression % fieldname

    def generateNotNULLValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateBefore(self, parsed):
        return "stream=%s where " % self.table

    def getTable(self, parsed_rule_data):
        logsource_data = parsed_rule_data.get('logsource')
        if logsource_data.get('category'):
            self.table = logsource_data.get('category')
        elif logsource_data.get('product'):
            self.table = logsource_data.get('product')
        elif logsource_data.get('service'):
            self.table = logsource_data.get('service')

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        parsed_yaml = sigmaparser.parsedyaml
        if parsed_yaml.get('detection').get('timeframe'):
            self.timeframe = parsed_yaml['detection']['timeframe']

        if sigmaparser.get_logsource() and sigmaparser.get_logsource().index:
            self.table = sigmaparser.get_logsource().index[0]
        else:
            self.getTable(parsed_yaml)
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if result.endswith(" | "):
                result = result.strip(" | ")
            return result
