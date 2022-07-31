# Output backends for sigmac
# Copyright 2022 Antonio Blescia (a.blescia@nocommentlab.it)

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

# Based on csharp backend written by Danijel Grah (dgrah@nil.com)

import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin

class HederaBackend(SingleTextQueryBackend):
    """Converts Sigma rule into CSharp Regex in Dynamic LINQ query."""
    identifier = "hedera"
    active = True
    config_required = False
    default_config = ["sysmon"]
    

    reEscape = re.compile('((?<!\\\\)\\\\(?![*?\\\\])|([\+\?\(\)]))')
    reClear = None
    andToken = " && "
    orToken = " || "
    notToken = " ! "
    subExpression = "(%s)"
    valueExpression = "\"%s\""
    nullExpression = "! %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True

    logname = None

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)
            lambda_preface = self.generateBefore(parsed)

            result = ""

            if lambda_preface is not None:
                result = lambda_preface
            if query is not None:
                result += query

            return result

    def generateBefore(self, parsed):
        
        return "x=>"

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

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        self.parsedlogsource = sigmaparser.get_logsource().service

        if parsed.parsedAgg:
            raise NotImplementedError("Aggregation function is NOT implemented for this backend")
            
        else:
            return result
        
        

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            
            if key in ("LogName","source"):
                self.logname = value
            elif key in ("EventID","x.Key"):
                key = "x.Key"
                return self.mapExpression % (key, self.generateValueNode(value, True))
            elif (type(value) == str and "\"" in value) or (type(value) == str and "*" in value) or (type(value) == str and "?" in value):
                value = value.replace("\"", "\"\"").replace("*", ".*").replace("?","\?")
                return "new Regex(@%s, RegexOptions.IgnoreCase).IsMatch(x.Value)" % (self.generateValueNode(key +".*"+ value, True))
            
            elif type(value) in (str, int):
                return "new Regex(@%s, RegexOptions.IgnoreCase).IsMatch(x.Value)" % (self.generateValueNode(key +".*"+ str(value), True))
            else:
                return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        elif value is None:
            return self.nullExpression % (key, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
          
            if key in ("EventID","x.Key"):               
                key = "x.Key"
                itemslist.append(self.mapExpression % (key, self.generateValueNode(item, True)))
            
            elif (type(item) == str and "\"" in item) or (type(item) == str and "*" in item) or (type(item) == str and "?" in item):
                item = item.replace("\"", "\"\"").replace("*", ".*").replace("?","\?")
                itemslist.append("new Regex(@%s, RegexOptions.IgnoreCase).IsMatch(x.Value)" % (self.generateValueNode(key +".*"+ item, True)))                    

            else:
                itemslist.append("new Regex(@%s, RegexOptions.IgnoreCase).IsMatch(x.Value)" % (self.generateValueNode(key +".*"+ item, True)))  
         
        return '('+" | ".join(itemslist)+')'

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateValueNode(self, node, keypresent):
        if keypresent == False:
            return "new Regex(@\"{0}\", RegexOptions.IgnoreCase).IsMatch(x.Value)".format(str(node))
        else:
            return self.valueExpression % (self.cleanValue(str(node)))
  
    