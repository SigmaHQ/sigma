# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Roey

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
# from netaddr import *
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin
from sigma.parser.modifiers.base import SigmaTypeModifier
import requests
# import argparse
import urllib3
import json
from .. eventdict import event
urllib3.disable_warnings()
import os, ssl
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
    getattr(ssl, '_create_unverified_context', None)): 
    ssl._create_default_https_context = ssl._create_unverified_context
ssl._create_default_https_context = ssl._create_unverified_context
# parser = argparse.ArgumentParser()
# parser.add_argument("--eshost", help="Elasticsearch host", type=str, required=True)
# parser.add_argument("--esport", help="Elasticsearch port", type=str, required=True)
# parser.add_argument("--ruledir", help="sigma rule directory path to convert", type=str, required=True)
# parser.add_argument("--index", help="Elasticsearch index name egs: \"winlogbeat-*\"", type=str, required=True)
# parser.add_argument("--email", help="email address to send mail alert", type=str, required=True)
# parser.add_argument("--outdir", help="output directory to create elastalert rules", type=str, required=True)
# parser.add_argument("--sigmac", help="Sigmac location", default="../tools/sigmac", type=str)
# parser.add_argument("--realerttime", help="Realert time (optional value, default 5 minutes)", type=str, default=5)
# parser.add_argument("--debug", help="Show debug output", type=bool, default=False)
# args = parser.parse_args()
class CarbonBlackBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Carbon Black Query Language (SPL)."""
    identifier = "carbonblack"
    active = True
    index_field = "index"

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " and "
    orToken = " OR "
    notToken = "-"
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "- %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s:%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, key, value):
        if(key == "EventID"):
            return ("( OR ".join(['%s:%s )' % (self.generateEventKey(item), self.generateEventValue(item)) for item in value if self.generateEventKey(item)!= '']))

        elif not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(" + (" OR ".join(['%s:%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateMapItemNode(self, node):
        fieldname, value = node
        value = self.cleanValue(value)
        print(str(value))
        if(fieldname == "EventID" and (type(value) is str or type(value) is int )):
            fieldname = self.generateEventKey(value)
            value = self.generateEventValue(value)
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if(transformed_fieldname == "ipaddr"):
            value = self.cleanIPRange(value)
        if(transformed_fieldname == ''):
            return ''
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))


    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val | search val %s %s" % (agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val by %s| search val %s %s" % (agg.groupfield, agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)

    def cleanValue(self, value):
        new_value = value
        if type(value) is str:
            if (new_value[:2] in ("*\/","*\\")):
                new_value = new_value[2:]
            if (new_value[:1] == '*'):
                new_value = new_value.replace("*", "", 1)
            if ( "1 to" not in new_value):    
                new_value = new_value.replace("* ", "*")
                new_value = new_value.replace(" *", "*")
                new_value = new_value.replace('"', '\"')
            # need tuning    
            if (( "(" in new_value or " " in new_value or ")" in new_value or ":" in new_value) and "1 to" not in new_value):
                if (new_value[0] != '"' and new_value[-1] != '"'):
                    new_value = '"' + new_value +'"'
                new_value = new_value.replace("(", "\(")
                new_value = new_value.replace(")", "\)")
                new_value = new_value.replace(" ", "\ ")

            new_value = new_value.strip()
        if type(value) is list:
            for vl in value:
                vl = self.cleanValue(vl)
        return new_value

    def generateEventKey(self, value):
        if (value in event):
            return event[value][0]
        else:
            return ''

    def generateEventValue(self, value):
        if (value in event):
            return event[value][1]
        else:
            return ''

    def cleanIPRange(self,value):
        new_value = value
        if type(value) is str and value.find('*') :
            sub =  value.count('.')
            if(value[-2:] == '.*'):
                value = value[:-2]
            min_ip = value + '.0' * (4 - sub)
            max_ip = value + '.255' * (4 - sub)
            new_value = '['+ min_ip + ' TO ' + max_ip + ']'
            # ip = IPNetwork(value + '/' + str(sub))
            # min_ip = str(ip[0])
            # max_ip = str(ip[-1])
        if type(value) is list:
            for vl in value:
                vl = self.cleanIPRange(vl)
        return new_value

    def postAPI(self,result,title,desc):
        url = 'https://10.14.132.6//api/v1/watchlist'
        body = {
                "name":title,
                "search_query":"q="+str(result),
                "description":desc,
                "index_type":"events"
                }
        header = {
            "X-Auth-Token": "6ff62a0dd9cf895b806fbd3190f3c0b18d98a9ae"
        }
        print(title)
        x = requests.post(url, data =json.dumps(body), headers = header, verify=False)

        print(x.text)

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        columns = list()
        title = sigmaparser.parsedyaml["title"]
        desc = sigmaparser.parsedyaml["description"]
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            # print(query.replace("\\\\","\\"))
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            # if mapped is not None:
            #     result += fields
            # self.postAPI(result,title,desc)
            # print (title)
            # print (str(result))
            return result