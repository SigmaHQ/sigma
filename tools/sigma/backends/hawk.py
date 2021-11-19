# Output backends for sigmac 
# Copyright 2021 HAWK.io

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



import re
import sigma
import json
import uuid
import re
from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class HAWKBackend(SingleTextQueryBackend):
    """Converts Sigma rule into HAWK search"""
    identifier = "hawk"
    active = True
    config_required = False
    default_config = ["sysmon", "hawk"]
    reEscape = re.compile('(")')
    logname = None
    reClear = None
    andToken = " , "
    orToken = " , "
    subExpression = "{\"id\": \"and\", \"key\": \"And\", \"children\": [%s] }"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    keyExpression = "%s"
    nullExpression = "%s = null"
    notNullExpression = "%s != null"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    aql_database = "events"

    def cleanKey(self, key):
        if key == None:
            return ""
        return self.sigmaparser.config.get_fieldmapping(key).resolve_fieldname(key, self.sigmaparser)

    def cleanValue(self, value):
        """Remove quotes in text"""
        return value

    def generateNode(self, node, notNode=False):
        #print(type(node))
        #print(node)
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node, notNode)
        elif type(node) == sigma.parser.condition.ConditionOR:
            #print("OR NODE")
            #print(node)
            return self.generateORNode(node, notNode)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            #print("NOT NODE")
            #print(node)
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node, notNode)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            #print(node)
            return self.generateSubexpressionNode(node, notNode)
        elif type(node) == tuple:
            #print("TUPLE: ", node)
            return self.generateMapItemNode(node, notNode)
        elif type(node) in (str, int):
            nodeRet = {"key": "",  "description": "", "class": "column", "return": "str", "args": { "comparison": { "value": "=" }, "str": { "value": "5", "regex": "true" } } }
            #key = next(iter(self.sigmaparser.parsedyaml['detection'])) 
            key = "payload"

            #nodeRet['key'] = self.cleanKey(key).lower()
            nodeRet['key'] = key

            #print(node)
            #print("KEY: ", key)
            # they imply the entire payload
            nodeRet['description'] = key
            nodeRet['rule_id'] = str(uuid.uuid4())
            value = self.generateValueNode(node, False).replace("*", "EEEESTAREEE")
            value = re.escape(value)
            value = value.replace("EEEESTAREEE", ".*")
            if value[0:2] == ".*":  
                value = value[2:]
            if value[-2:] == ".*":
                value = value[:-2]
            nodeRet['args']['str']['value'] = value 
            # return json.dumps(nodeRet)
            return nodeRet
        elif type(node) == list:
            return self.generateListNode(node, notNode)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generateANDNode(self, node, notNode=False):
        """
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            return self.andToken.join(filtered)
        else:
            return None
        """
        ret = { "id" : "and", "key": "And", "children" : [ ] }
        generated = [ self.generateNode(val, notNode) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            ret['children'] = filtered
            # return json.dumps(ret)# self.orToken.join(filtered)
            return ret
        else:
            return None

    def generateORNode(self, node, notNode=False):
        if notNode:
            ret = { "id" : "and", "key": "And", "children" : [ ] }
        else:
            ret = { "id" : "or", "key": "Or", "children" : [ ] }
        generated = [ self.generateNode(val, notNode) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            if self.sort_condition_lists:
                filtered = sorted(filtered)
            ret['children'] = filtered

            # retAnd['children'].append( ret )
            #return retAnd
            return ret
        else:
            return None

    def generateSubexpressionNode(self, node, notNode=False):
        generated = self.generateNode(node.items, notNode)
        if 'len'in dir(node.items): # fix the "TypeError: object of type 'NodeSubexpression' has no len()"
            if len(node.items) == 1:
                # A sub expression with length 1 is not a proper sub expression, no self.subExpression required
                return generated
        if generated:
            return json.loads(self.subExpression % json.dumps(generated))
        else:
            return None

    def generateListNode(self, node, notNode=False):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        result = [self.generateNode(value, notNode) for value in node]
        if len(result) == 1:
            # A list with length 1 is not a proper list, no self.listExpression required
            return result[0]
        #print("LIST EXPRESSION")
        #print(result)
        return self.listExpression % (self.listSeparator.join(result))

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item, True)
        return generated

    def generateMapItemNode(self, node, notNode=False):
        nodeRet = {"key": "",  "description": "", "class": "column", "return": "str", "args": { "comparison": { "value": "=" }, "str": { "value": 5 } } }
        if notNode:
            nodeRet["args"]["comparison"]["value"] = "!="
        nodeRet['rule_id'] = str(uuid.uuid4())
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            nodeRet['key'] = self.cleanKey(key).lower()
            nodeRet['description'] = key
            if key.lower() in ("logname","source"):
                self.logname = value
            elif type(value) == str and "*" in value:
                value = value.replace("*", "EEEESTAREEE")
                value = re.escape(value)
                value = value.replace("EEEESTAREEE", ".*")
                if value[0:2] == ".*":  
                    value = value[2:]
                if value[-2:] == ".*":
                    value = value[:-2]
                if notNode:
                    nodeRet["args"]["comparison"]["value"] = "!="
                else:
                    nodeRet['args']['comparison']['value'] = "="
                nodeRet['args']['str']['value'] = value
                nodeRet['args']['str']['regex'] = "true"
                # return "%s regex %s" % (self.cleanKey(key), self.generateValueNode(value, True))
                #return json.dumps(nodeRet)
                return nodeRet
            elif type(value) is str:
                #return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value, True))
                nodeRet['args']['str']['value'] = value
                # return json.dumps(nodeRet)
                return nodeRet
            elif type(value) is int:
                nodeRet['return'] = "int"
                nodeRet['args']['int'] = { "value" : value }
                del nodeRet['args']['str'] 
                #return self.mapExpression % (self.cleanKey(key), self.generateValueNode(value, True))
                #return json.dumps(nodeRet)
                return nodeRet
            else:
                #return self.mapExpression % (self.cleanKey(key), self.generateNode(value))
                nodeRet['args']['str']['value'] = value
                #return json.dumps(nodeRet)
                return nodeRet
        elif type(value) == list:
            return self.generateMapItemListNode(key, value, notNode)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(key, value)
        elif value is None:
            #return self.nullExpression % (key, )
            #print("Performing null")
            #print(notNode)
            #print(key)
            nodeRet = { "key" : "empty", "description" : "Value Does Not Exist (IS NULL)", "class" : "function", "inputs" : { "comparison" : { "order" : 0, "source" : "comparison", "type" : "comparison" }, "column" : { "order" : 1, "source" : "columns", "type" : "str" } }, "args" : { "comparison" : { "value" : "!=" }, "column" : { "value" : "" } }, "return" : "boolean" }
            nodeRet['args']['column']['value'] = self.cleanKey(key).lower()
            nodeRet['description'] += " %s" % key
            if notNode:
                nodeRet['args']['comparison']['value'] = "!="
            else:
                nodeRet['args']['comparison']['value'] = "="
            #return json.dumps(nodeRet)
            #print(json.dumps(nodeRet))
            return nodeRet
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value, notNode=False):
        if notNode:
            ret = { "id" : "and", "key": "And", "children" : [ ] }
        else:
            ret = { "id" : "or", "key": "Or", "children" : [ ] }
        for item in value:
            nodeRet = {"key": "",  "description": "", "class": "column", "return": "str", "args": { "comparison": { "value": "=" }, "str": { "value": "5" } } }
            nodeRet['key'] = self.cleanKey(key).lower()
            nodeRet['description'] = key
            nodeRet['rule_id'] = str(uuid.uuid4())
            if item is None:
                nodeRet['args']['str']['value'] = 'null'
                ret['children'].append( nodeRet )
            elif type(item) == str and "*" in item:
                item = item.replace("*", "EEEESTAREEE")
                item = re.escape(item)
                item = item.replace("EEEESTAREEE", ".*")
                if item[:2] == ".*":  
                    item = item[2:]
                if item[-2:] == ".*":
                    item = item[:-2]
                nodeRet['args']['str']['value'] = item # self.generateValueNode(item, True)
                nodeRet['args']['str']['regex'] = "true"
                if notNode:
                    nodeRet["args"]["comparison"]["value"] = "!="
                else:
                    nodeRet['args']['comparison']['value'] = "="
                ret['children'].append( nodeRet )
            else:
                nodeRet['args']['str']['value'] = self.generateValueNode(item, True)
                ret['children'].append( nodeRet )
        retAnd = { "id" : "and", "key": "And", "children" : [ ret ] }
        return retAnd # '('+" or ".join(itemslist)+')'
        # return json.dumps(ret) # '('+" or ".join(itemslist)+')'

    def generateMapItemTypedNode(self, fieldname, value, notNode=False):
        nodeRet = {"key": "",  "description": "", "class": "column", "return": "str", "args": { "comparison": { "value": "=" }, "str": { "value": "5" } } }
        nodeRet['key'] = self.cleanKey(fieldname).lower()
        nodeRet['description'] = fieldname
        nodeRet['rule_id'] = str(uuid.uuid4())
        if type(value) == SigmaRegularExpressionModifier:
            value = str(value)
            value = value.replace("*", "EEEESTAREEE")
            value = re.escape(self.generateValueNode(value, True))
            value = value.replace("EEEESTAREEE", ".*")
            if value[:2] == ".*":  
                value = value[2:]
            if value[-2:] == ".*":
                value = value[:-2]
            nodeRet['args']['str']['value'] = value
            nodeRet['args']['str']['regex'] = "true"
            if notNode:
                nodeRet["args"]["comparison"]["value"] = "!="
            else:
                nodeRet['args']['comparison']['value'] = "="
            return nodeRet
        else:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(value.identifier))

    def generateValueNode(self, node, keypresent):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node, notNode):
        # node.item
        nodeRet = { "key" : "empty", "description" : "Value Does Not Exist (IS NULL)", "class" : "function", "inputs" : { "comparison" : { "order" : 0, "source" : "comparison", "type" : "comparison" }, "column" : { "order" : 1, "source" : "columns", "type" : "str" } }, "args" : { "comparison" : { "value" : "!=" }, "column" : { "value" : node.item } }, "return" : "boolean" }
        nodeRet['args']['column']['value'] = self.cleanKey(node.item).lower()
        nodeRet['description'] += " %s" % key
        if notNode:
            nodeRet['args']['comparison']['value'] = "!="
        else:
            nodeRet['args']['comparison']['value'] = "="
        nodeRet['rule_id'] = str(uuid.uuid4())
        # return json.dumps(nodeRet)
        return nodeRet

    def generateNotNULLValueNode(self, node):
        # return self.notNullExpression % (node.item)
        return node.item

    def generateAggregation(self, agg, timeframe='00'):
        if agg == None:
            return None
        #print(agg.aggfunc)
        #print(type(agg.aggfunc))
        #print(agg.aggfunc_notrans)
        if not agg.aggfunc_notrans.lower() in ("count", "sum"):
            raise NotImplementedError("This aggregation operator '%s' has not been implemented" % agg.aggfunc_notrans)

        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            return None

        if agg.groupfield == None:
            agg.groupfield = "priority"

        if agg.groupfield != None and timeframe == '00':
            self.prefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
            self.suffixAgg = " group by %s having agg_val %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition)
            #print("Group field and timeframe is 00")
            min_count = 60
            nodeRet = {"key": "atomic_counter",  "description": self.cleanKey(agg.groupfield) + " %s aggregation stream counter" % agg.aggfunc_notrans, "class": "function", "return": "int",
                 "inputs": {
                     "columns" : { "order" : "0", "source" : "columns", "type" : "array", "objectKey" : "columns" },
                     "comparison" : { "order" : "1", "source" : "comparison", "type" : "comparison", "objectKey" : "comparison" },
                     "threshold" : { "order" : "2", "source" : "", "type" : "int", "objectKey" : "threshold" },
                     "limit" : { "order" : "3", "source" : "time_offset", "type" : "int", "objectKey" : "limit" },
                 },
                 "args": { 
                     "columns" : [ self.cleanKey(agg.groupfield) ],
                     "comparison": { "value": "%s" % agg.cond_op }, 
                     "threshold": { "value": int(agg.condition) }, 
                     "limit": { "value": min_count } 
                 } 
            }
            nodeRet['rule_id'] = str(uuid.uuid4())
            #print("No time range set")
            return nodeRet
        elif agg.groupfield != None and timeframe != None:
            for key, duration in self.generateTimeframe(timeframe).items():
                min_count = 60
                if key.lower() == 'hours':
                    min_count = 24 * int(duration)
                nodeRet = {"key": "atomic_counter",  "description": self.cleanKey(agg.groupfield) + " %s aggregation stream counter" % agg.aggfunc_notrans, "class": "function", "return": "int",
                         "inputs": {
                             "columns" : { "order" : "0", "source" : "columns", "type" : "array", "objectKey" : "columns" },
                             "comparison" : { "order" : "1", "source" : "comparison", "type" : "comparison", "objectKey" : "comparison" },
                             "threshold" : { "order" : "2", "source" : "", "type" : "int", "objectKey" : "threshold" },
                             "limit" : { "order" : "3", "source" : "time_offset", "type" : "int", "objectKey" : "limit" },
                         },
                         "args": { 
                             "columns" : [ self.cleanKey(agg.groupfield) ],
                             "comparison": { "value": "%s" % agg.cond_op }, 
                             "threshold": { "value": int(agg.condition) }, 
                             "limit": { "value": min_count } 
                         } 
                    }
                nodeRet['rule_id'] = str(uuid.uuid4())
                #self.prefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
                #self.suffixAgg = " group by %s having agg_val %s %s LAST %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition, duration, key)
                #print("Group field and timeframe")
                #return self.prefixAgg, self.suffixAgg
                return nodeRet
        else:
            self.prefixAgg = " SELECT %s(%s) as agg_val from %s where " % (agg.aggfunc_notrans, self.cleanKey(agg.aggfield), self.aql_database)
            self.suffixAgg = " group by %s having agg_val %s %s" % (self.cleanKey(agg.groupfield), agg.cond_op, agg.condition)
            #print("Last option")
            raise NotImplementedError("The 'agg' aggregation operator is not yet implemented for this backend") 
            return self.prefixAgg, self.suffixAgg
        #print(agg)
        raise NotImplementedError("The 'agg' aggregation operator is not yet implemented for this backend") 

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

    def generateBefore(self, parsed):
        if self.logname:
            return self.logname
        return self.logname

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        columns = list()
        mapped =None
        #print(sigmaparser.parsedyaml)
        self.logsource = sigmaparser.parsedyaml.get("logsource") if sigmaparser.parsedyaml.get("logsource") else sigmaparser.parsedyaml.get("logsources", {})
        fields = ""
        try:
            #print(sigmaparser.parsedyaml["fields"])
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")

            fields = ",".join(str(x) for x in columns)
            fields = " | table " + fields

        except KeyError:    # no 'fields' attribute
            mapped = None
            pass

        #print("Mapped: ", mapped)
        #print(sigmaparser.parsedyaml)
        #print(sigmaparser.condparsed)
        #print("Columns: ", columns)
        #print("Fields: ", fields)
        #print("Logsource: " , self.logsource)

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            #print("Before: ", before)

            #print("Query: ", query)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            return result

    def dedupeAnds(self, arr, parentAnd=False):
        # simple dedupe
        for i in range(0, len(arr)):
            if 'id' in arr[i] and arr[i]['id'].lower() == "and":
                arr[i]['children'] = self.dedupeAnds(arr[i]['children'])

                if len(arr[i]['children']) == 1 and 'id' in arr[i]['children'][0] and arr[i]['children'][0]['id'].lower() == "and":
                    arr[i] = arr[i]['children'][0]


        return arr

        """
        for i in range(0, len(arr)):
            if parentAnd and 'id' in arr[i] and arr[i]['id'].lower() == "and":
                isAnd = True
            else:
                isAnd = False
            
            if 'children' in arr[i]:
                arr[i]['children'] = self.dedupeAnds(arr['i']['children'], isAnd)

            if parentAnd and 'id' in arr[i] and arr[i]['id'].lower() == "and":
                pass

        if len(arr) == 1 and 'id' in arr[0] and arr[0]['id'].lower() == "and":
            # print("Returning less!")
            for i in range(0, len(arr) ):
                if 'id' in arr[i] and arr[i]['id'].lower() == "and":
                    arr[i]['children'] = self.dedupeAnds(arr[i]['children'])
            return arr[0]['children']

        """
        return arr

    """
    def dedupeAnds(self, arr, parentAnd=False):
        #if not parentAnd:
        #    for i in range(0, len(arr) ):
        #        if 'id' in arr[i] and arr[i]['id'].lower() == "and":
        #            arr[i]['children'] = self.dedupeAnds(arr[i]['children'], False)

        if len(arr) == 1 and 'id' in arr[0] and arr[0]['id'].lower() == "and":
            # print("Returning less!")
            for i in range(0, len(arr) ):
                if 'id' in arr[i] and arr[i]['id'].lower() == "and":
                    arr[i]['children'] = self.dedupeAnds(arr[i]['children'])
            return arr[0]['children']

        allAndCheck = True
        for i in range(0, len(arr) ):
            # print(arr[i])
            if 'id' in arr[i] and arr[i]['id'].lower() == "and":
                arr[i]['children'] = self.dedupeAnds(arr[i]['children'])
            else:
                allAndCheck = False


        x = [ ]
        if allAndCheck:
            for i in range(0, len(arr)):
                x = x + arr[i]['children']
            return x
        return arr
    """

    def generateQuery(self, parsed, sigmaparser):
        self.sigmaparser = sigmaparser
        result = self.generateNode(parsed.parsedSearch)
        """
        if any("flow" in i for i in self.parsedlogsource):
            aql_database = "flows"
        else:
            aql_database = "events"
        """
        prefix = ""
        ret = '[ { "id" : "and", "key": "And", "children" : ['
        ret2 = ' ] } ]'
        try:
            mappedFields = []
            for field in sigmaparser.parsedyaml["fields"]:
                    mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                    #print(mapped)
                    mappedFields.append(mapped)
                    if " " in mapped and not "(" in mapped:
                        prefix += ", \"" + mapped + "\""
                    else:
                        prefix +=  ", " + mapped

        except KeyError:    # no 'fields' attribute
            mapped = None
            pass

        try:
            timeframe = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            timeframe = None

        if parsed.parsedAgg and timeframe == None:
            addition = self.generateAggregation(parsed.parsedAgg)
            #print(addition)
            #print(result)
            if addition:
                if not 'children' in result:
                    rec = self.subExpression % json.dumps(result)
                    result = json.loads(rec)
                    #print(result)
                result['children'].append(addition)
            elif parsed.parsedAgg:
                #print(result)
                raise Exception("No agg returned, something is off")
        elif parsed.parsedAgg != None and timeframe != None:
            addition = self.generateAggregation(parsed.parsedAgg, timeframe)
            #print(addition)
            #print(result)
            if addition:
                #print(result)
                if not 'children' in result:
                    rec = self.subExpression % json.dumps(result)
                    result = json.loads(rec)
                    #print(result)
                result['children'].append(addition)
            elif parsed.parsedAgg:
                #print(result)
                raise Exception("No agg returned, something is off")
        else:
            # result = prefix + result
            pass

        result = json.dumps(result)

        analytic_txt = ret + result + ret2 # json.dumps(ret)
        try:
            analytic = json.loads(analytic_txt) # json.dumps(ret)
            # analytic = self.dedupeAnds(analytic)
            analytic[0]['children'] = self.dedupeAnds(analytic[0]['children'], True)

        except Exception as e:
            print("Failed to parse json: %s" % analytic_txt)
            raise Exception("Failed to parse json: %s" % analytic_txt)
        # "rules","filter_name","actions_category_name","correlation_action","date_added","scores/53c9a74abfc386415a8b463e","enabled","public","group_name","score_id"

        cmt = "Sigma Rule: %s\n" % sigmaparser.parsedyaml['id'] 
        cmt += "Author: %s\n" % sigmaparser.parsedyaml['author'] 
        cmt += "Level: %s\n" % sigmaparser.parsedyaml['level'] 
        if 'falsepositives' in sigmaparser.parsedyaml and type(sigmaparser.parsedyaml['falsepositives']) is list:
            if len(sigmaparser.parsedyaml['falsepositives']) > 0:
                cmt += "False Positives: "
                for v in sigmaparser.parsedyaml['falsepositives']:
                    if v:
                        cmt += "%s, " % v
                    else:
                        cmt += "None, "
                cmt = cmt[:-2] + "\n"
        elif 'falsepositives' in sigmaparser.parsedyaml and sigmaparser.parsedyaml['falsepositives']:
            raise Exception("Unknown type for false positives: ", type(sigmaparser.parsedyaml['falsepositives']))

        if 'references' in sigmaparser.parsedyaml:
            ref = "%s\n" % "\n".join(sigmaparser.parsedyaml['references']) 
        else:
            ref = ''
        record = {
            "rules" : analytic, # analytic_txt.replace('"','""'),
            "filter_name" : sigmaparser.parsedyaml['title'],
            "filter_details" : cmt,
            "actions_category_name" : "Add (+)",
            "correlation_action" : 5.00,
            "date_added" : sigmaparser.parsedyaml['date'],
            "enabled" : False,
            # "enabled" : True,
            "public" : True,
            "references" : ref,
            "group_name" : ".",
            "hawk_id" : sigmaparser.parsedyaml['id']
        }
        if 'tags' in sigmaparser.parsedyaml:
            record["tags"] = [ item.replace("attack.", "") for item in sigmaparser.parsedyaml['tags']]

        if not 'status' in self.sigmaparser.parsedyaml or 'status' in self.sigmaparser.parsedyaml and self.sigmaparser.parsedyaml['status'] != 'experimental':
            record['correlation_action'] += 10.0;
        if 'falsepositives' in self.sigmaparser.parsedyaml and len(self.sigmaparser.parsedyaml['falsepositives']) > 1:
            record['correlation_action'] -= (2.0 * len(self.sigmaparser.parsedyaml['falsepositives']) )

        if 'level' in self.sigmaparser.parsedyaml:
            if self.sigmaparser.parsedyaml['level'].lower() == 'critical':
                record['correlation_action'] += 15.0;
            elif self.sigmaparser.parsedyaml['level'].lower() == 'high':
                record['correlation_action'] += 10.0;
            elif self.sigmaparser.parsedyaml['level'].lower() == 'medium':
                record['correlation_action'] += 5.0;
            elif self.sigmaparser.parsedyaml['level'].lower() == 'low':
                record['correlation_action'] += 2.0;
       
        return json.dumps(record)
