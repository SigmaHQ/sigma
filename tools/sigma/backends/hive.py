import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class HiveBackend(SingleTextQueryBackend):
    """Converts Sigma rule into hive query. Contributed by M0jtaba"""
    identifier = "hive"
    active = True
    reEscape = None
    reClear = None
    andToken = " AND "
    orToken = "\'|\'"
    notToken = "NOT "
    subExpression = "%s"
    listExpression = "(%s)"
    listSeparator = ","
    valueExpression = "\'%s\'"
    keyExpression = "%s"
    nullExpression = "%s IS NULL"
    notNullExpression = "%s IS NOT NULL"
    mapExpression = "%s=\'%s\'"
    mapListsSpecialHandling = False

    def cleanKey(self, key):
        if " " in key:
            key = "\"%s\"" % (key)
            return key
        else:
            return key

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
            return self.generateValueNode(node, False)
        elif type(node) == list:
            return self.generateListNode(node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generateMapItemNode(self, node):
        fieldname, value = node
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if (self.mapListsSpecialHandling == False and
            type(value) in (str, int, list) or
            self.mapListsSpecialHandling == True and
            type(value) in (str, int)):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        else:
            raise TypeError("Backend does not support map values of type " +
                            str(type(value)) + "  " + str(value))

    def generateMapItemListNode(self, fieldname, value):
        return self.mapListValueExpression % (fieldname, self.generateNode(value))

    def generateValueNode(self, node, keypresent):
        if keypresent == False:
            data = "{0}".format(self.cleanValue(str(node)))
            return data
        else:
            return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def generateAggregation(self, agg, hive_database, event_id, timeframe=None):
        self.hive_database = hive_database
        event_id = event_id.split('=')
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield is None:
            self.hive_prefix_agg = "SELECT a.count FROM ( SELECT COUNT(DISTINCT %s) as count FROM %s WHERE" % (event_id[0], self.hive_database)
            self.hive_suffix_agg = "AS a WHERE a.count %s %s" % (agg.cond_op, agg.condition)
            return self.hive_prefix_agg, self.hive_suffix_agg
        elif agg.groupfield is not None and timeframe is None:
            self.hive_prefix_agg = " SELECT a.name, a.count FROM ( SELECT %s as name, COUNT(DISTINCT %s) as count FROM %s WHERE " % (agg.groupfield, event_id[0], self.hive_database)
            self.hive_suffix_agg = " GROUP BY name ) AS a WHERE a.count %s %s" % (agg.cond_op, agg.condition)
            return self.hive_prefix_agg, self.hive_suffix_agg
        elif agg.groupfield is not None and timeframe is not None:
            for key, duration in self.generateTimeframe(timeframe).items():
                if 'days' in key:
                    self.hive_prefix_agg = " SELECT a.name, a.count FROM ( SELECT %s as name, COUNT(DISTINCT %s) as count FROM %s WHERE " % (agg.groupfield, event_id[0], self.hive_database)
                    self.hive_suffix_agg = " AND to_date(event_ts) >= date_sub(current_date, %s) AND to_date(event_ts) < current_date GROUP BY name ) AS a WHERE a.count %s %s" % (duration, agg.cond_op, agg.condition)
                    return self.hive_prefix_agg, self.hive_suffix_agg
                elif 'seconds' in key:
                    raise NotImplementedError("The 'seconds' timeframe is not yet implemented for this backend")
                elif 'minutes' in key:
                    raise NotImplementedError("The 'minutes' timeframe is not yet implemented for this backend")
                elif 'hours' in key:
                    raise NotImplementedError("The 'hours' timeframe is not yet implemented for this backend")
                elif 'months' in key:
                    raise NotImplementedError("The 'months' timeframe is not yet implemented for this backend")
        else:
            raise NotImplementedError("The aggregation operator is not yet implemented for this backend")

    def generateTimeframe(self, timeframe):
        time_unit = timeframe[-1:]
        duration = timeframe[:-1]
        timeframe_object = {}
        if time_unit == "s":
            timeframe_object['seconds'] = int(duration)
        elif time_unit == "m":
            timeframe_object['minutes'] = int(duration)
        elif time_unit == "h":
            timeframe_object['hours'] = int(duration)
        elif time_unit == "d":
            timeframe_object['days'] = int(duration)
        else:
            timeframe_object['months'] = int(duration)
        return timeframe_object

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
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

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        try:
            if sigmaparser.parsedyaml['table']:
                hive_database = sigmaparser.parsedyaml['table']
        except:
            hive_database = "<TableName>"
        hive_prefix = "SELECT * from %s where " % (hive_database)
        try:
            timeframe = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            timeframe = None
        if parsed.parsedAgg != None and timeframe == None:
            (hive_prefix, hive_suffix_agg) = self.generateAggregation(parsed.parsedAgg, hive_database, result)
            result = hive_prefix + result
            result += hive_suffix_agg
            return result
        elif parsed.parsedAgg != None and timeframe != None:
            (hive_prefix, hive_suffix_agg) = self.generateAggregation(parsed.parsedAgg, hive_database, result, timeframe)
            result = hive_prefix + result
            result += hive_suffix_agg
            return result
        elif 'AND NOT' in result and "|" in result and 'EventID' not in result:
            splitter = result.replace('|', ', ').split('AND NOT')
            result = ("%s <ColumnFieldName> IN ('%s') AND <ColumnFieldName> NOT IN ('%s')") % (hive_prefix, splitter[0].rstrip(), splitter[1].lstrip())
            return result
        elif re.search(r"^EventID='(.*?)'", result) and 'LogonType' not in result:
            event_ids = re.search(r"^EventID='(.*?)'", result)
            event_ids_split = event_ids.group(0).split('EventID=')
            event_ids_split = event_ids_split[1].strip('\'').strip('(').strip(')').split(',')
            event_id = ', '.join("'{}'".format(i) for i in event_ids_split)
            temp_result = "EventID IN (%s)" % (event_id)
            if 'AND' in result:
                temp_value = result.split('AND')
                result = hive_prefix + temp_result + ' AND ' + temp_value[1].lstrip()
            else:
                 raise NotImplementedError("The aggregation operator is not yet implemented for this backend")
            return result
        else:
            raise NotImplementedError("The aggregation operator is not yet implemented for this backend")
