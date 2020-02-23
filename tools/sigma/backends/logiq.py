import re
from .base import BaseBackend
from .mixins import QuoteCharMixin
import json

class LogiqBackend(BaseBackend, QuoteCharMixin):
    """Generates Perl compatible regular expressions and puts 'grep -P' around it"""
    identifier = "logiq"
    active = True
    config_required = False

    reEscape = re.compile("([\\|()\[\]{}.^$+])")

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        print ("XXXXXX LogiqBackend definitions",sigmaparser.definitions)
        print ("XXXXXX LogiqBackend values",sigmaparser.values)
        print ("XXXXXX LogiqBackend config",sigmaparser.config)

        eventRule = dict()
        eventRule["name"] = sigmaparser.parsedyaml["title"]
        eventRule["groupName"] = sigmaparser.parsedyaml["logsource"]["product"]
        eventRule["description"] = sigmaparser.parsedyaml["description"]
        eventRule["condition"] = sigmaparser.parsedyaml["detection"]
        eventRule["level"] = sigmaparser.parsedyaml["level"]


        for key,value in eventRule.items():
            print(key, ":", value)
        print ("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            eventRule["condition"] = ""
            if before is not None:
                eventRule["condition"] = before
            if query is not None:
                eventRule["condition"] += query
            if after is not None:
                eventRule["condition"] += after

            result = json.dumps(eventRule)

            return result

    def generateQuery(self, parsed):
        # print("generateQuery: ", parsed)
        return "%s" % self.generateNode(parsed.parsedSearch)

    def cleanValue(self, val):
        # val = super().cleanValue(val)
        if val[0] == '*':
            val = val.replace("*","/*")
        
        print("cleanValue: ", val)
        return val

    def generateORNode(self, node):
        print("generateORNode: ", node)
        return "%s" % " || ".join([self.generateNode(val) for val in node])

    def generateANDNode(self, node):
        print("generateORNode: ", node)
        return "%s" % " && ".join([self.generateNode(val) for val in node])
        
    def generateNOTNode(self, node):
        print("generateNOTNode: ", node)        
        return "%s" % self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        # print("generateSubexpressionNode: ", node)        
        return "%s" % self.generateNode(node.items)

    def generateListNode(self, node):
        # print("generateListNode: ", node)
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.generateORNode(node)

    def generateMapItemNode(self, node):
        print("generateMapItemNode: ", node)
        key, value = node
        if value is None:
            return self.generateNULLValueNode(node)
        else:
            return self.generateNode(value)

    def generateValueNode(self, node):
        print("generateValueNode: ", node)
        return "message =~ '" + self.cleanValue(str(node)).strip() + "'"

    def generateNULLValueNode(self, node):
        print("generateNULLValueNode: ", node)
        key, value = node
        return "%s" % key
