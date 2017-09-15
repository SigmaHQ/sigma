# Output backends for sigmac

import sys
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

### Output classes
class SingleOutput:
    """
    Single file output

    By default, this opens the given file or stdin and passes everything into this.
    """
    def __init__(self, filename=None):
        if type(filename) == str:
            self.fd = open(filename, "w")
        else:
            self.fd = sys.stdout

    def print(self, *args, **kwargs):
        print(*args, file=self.fd, **kwargs)

    def close(self):
        self.fd.close()

class MultiOutput:
    """
    Multiple file output

    Prepares multiple SingleOutput instances with basename + suffix as file names, on for each suffix.
    The switch() method is used to switch between these outputs.

    This class must be inherited and suffixes must be a dict as follows: file id -> suffix
    """
    suffixes = None

    def __init__(self, basename):
        """Initializes all outputs with basename and corresponding suffix as SingleOutput object."""
        if suffixes == None:
            raise NotImplementedError("OutputMulti must be derived, at least suffixes must be set")
        if type(basename) != str:
            raise TypeError("OutputMulti constructor basename parameter must be string")

        self.outputs = dict()
        self.output = None
        for name, suffix in self.suffixes:
            self.outputs[name] = SingleOutput(basename + suffix)

    def select(self, name):
        """Select an output as current output"""
        self.output = self.outputs[name]

    def print(self, *args, **kwargs):
        self.output.print(*args, **kwargs)

    def close(self):
        for out in self.outputs:
            out.close()

class StringOutput(SingleOutput):
    """Collect input silently and return resulting string."""
    def __init__(self, filename=None):
        self.out = ""

    def print(self, *args, **kwargs):
        try:
            del kwargs['file']
        except KeyError:
            pass
        print(*args, file=self, **kwargs)

    def write(self, s):
        self.out += s

    def result(self):
        return self.out

    def close(self):
        pass

### Generic backend base classes
class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False
    index_field = None    # field name that is used to address indices
    output_class = None   # one of the above output classes
    file_list = None

    def __init__(self, sigmaconfig, filename=None):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it. Further, output files are initialized by the output class defined in output_class.
        """
        if not isinstance(sigmaconfig, (sigma.SigmaConfiguration, None)):
            raise TypeError("SigmaConfiguration object expected")
        self.sigmaconfig = sigmaconfig
        self.sigmaconfig.set_backend(self)
        self.output = self.output_class(filename)

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            result = self.generateNode(parsed.parsedSearch)
            if parsed.parsedAgg:
                result += self.generateAggregation(parsed.parsedAgg)
            self.output.print(result)

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

    def generateAggregation(self, agg):
        raise NotImplementedError("Aggregations not implemented for this backend")

    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        pass

class SingleTextQueryBackend(BaseBackend):
    """Base class for backends that generate one text-based expression from a Sigma rule"""
    identifier = "base-textquery"
    active = False
    output_class = SingleOutput

    # the following class variables define the generation and behavior of queries from a parse tree some are prefilled with default values that are quite usual
    reEscape = None                     # match characters that must be quoted
    escapeSubst = "\\\\\g<1>"           # Substitution that is applied to characters/strings matched for escaping by reEscape
    reClear = None                      # match characters that are cleaned out completely
    andToken = None                     # Token used for linking expressions with logical AND
    orToken = None                      # Same for OR
    notToken = None                     # Same for NOT
    subExpression = None                # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = None               # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = None                # Character for separation of list items
    valueExpression = None              # Expression of values, %s represents value
    mapExpression = None                # Syntax for field/value conditions. First %s is key, second is value
    mapListsSpecialHandling = False     # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = None       # Syntax for field/value condititons where map value is a list

    def cleanValue(self, val):
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        if self.reClear:
            val = self.reClear.sub("", val)
        return val

    def generateANDNode(self, node):
        return self.andToken.join([self.generateNode(val) for val in node])

    def generateORNode(self, node):
        return self.orToken.join([self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return self.notToken + self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return self.mapListValueExpression % (key, self.generateNode(value))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

### Backends for specific SIEMs

class ElasticsearchQuerystringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([+\\-=!(){}\\[\\]^\"~:\\\\/]|&&|\\|\\|)")
    reClear = re.compile("[<>]")
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    mapExpression = "%s:%s"
    mapListsSpecialHandling = False

class KibanaBackend(ElasticsearchQuerystringBackend):
    """Converts Sigma rule into Kibana JSON Configuration files (Searches, Visualizations, Dashboards)."""
    identifier = "kibana"
    active = True
    output_class = SingleOutput

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kibanaconf = list()
        self.searches = set()

    def generate(self, sigmaparser):
        rulename = sigmaparser.parsedyaml["title"].replace(" ", "-")
        for parsed in sigmaparser.condparsed:
            result = self.generateNode(parsed.parsedSearch)
            if rulename in self.searches:   # add counter if name collides
                cnt = 0
                while "%s-%d" % (rulename, cnt) in self.searches:
                    cnt += 1
                rulename = "%s-%d" % (rulename, cnt)
            self.searches.add(rulename)

            try:
                description = sigmaparser.parsedyaml["description"]
            except KeyError:
                description = ""
            self.kibanaconf.append({
                    "_id": rulename,
                    "_type": "search",
                    "_source": {
                        "title": sigmaparser.parsedyaml["title"],
                        "description": description,
                        "hits": 0,
                        "columns": [],   # TODO: add columns used in search
                        "sort": ["@timestamp", "desc"],
                        "version": 1,
                        "kibanaSavedObjectMeta": {
                            "searchSourceJSON": json.dumps({
                                "index": "logstash-*",      # TODO: index from rule
                                "filter":  [],
                                "highlight": {
                                    "pre_tags": ["@kibana-highlighted-field@"],
                                    "post_tags": ["@/kibana-highlighted-field@"],
                                    "fields": { "*":{} },
                                    "require_field_match": False,
                                    "fragment_size": 2147483647
                                    },
                                "query": {
                                    "query_string": {
                                        "query": result,
                                        "analyze_wildcard": True
                                        }
                                    }
                                }
                            )
                        }
                    }
                })

    def finalize(self):
        self.output.print(self.kibanaconf)

class XpackWatcher(ElasticsearchQuerystringBackend):
    """Converts Sigma Rule into X-pack Watcher Json for alerting"""
    identifier = "xpack-watcher"
    active = True
    output_class = SingleOutput

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watcher_alert = dict()
        self.searches = set()

    def generate(self, sigmaparser):
        rulename = sigmaparser.parsedyaml["title"].replace(" ", "-")
        for parsed in sigmaparser.condparsed:
            result = self.generateNode(parsed.parsedSearch)
            if rulename in self.searches:   # add counter if name collides
                cnt = 0
                while "%s-%d" % (rulename, cnt) in self.searches:
                    cnt += 1
                rulename = "%s-%d" % (rulename, cnt)
            self.searches.add(rulename)
        # get the details if this alert occurs
        try:
            description = sigmaparser.parsedyaml["description"]
        except KeyError:
            description = ""
        try:
            false_positives = sigmaparser.parsedyaml["falsepositives"]
        except KeyError:
            false_positives = ""
        try:
            level = sigmaparser.parsedyaml["level"]
        except KeyError:
            level = ""
        logging_result = "Rule description: "+str(description)+", false positives: "+str(false_positives)+", level: "+level
        # Get time frame if exists
        try:
            interval = sigmaparser.parsedyaml["detection"]["timeframe"]
        except KeyError:
            interval = "30m"
        # creating condition
        try:
            condition = sigmaparser.parsedyaml["detection"]["condition"]
            if condition.find('>') != -1:
                alert_condition = {"gt": int(condition[condition.find('>')+2:])}
            else:
                alert_condition = {"not_eq": 0}
        except KeyError:
            alert_condition = {"not_eq": 0}

        self.watcher_alert[rulename] = {
                          "trigger": {
                            "schedule": {
                              "interval": interval  # how often the watcher should check
                            }
                          },
                          "input": {
                            "search": {
                              "request": {
                                "body": {
                                  "size": 0,
                                  "query": {
                                    "query_string": {
                                        "query": result,  # this is where the elasticsearch query syntax goes
                                        "analyze_wildcard": True
                                    }
                                  }
                                },
                                "indices": [
                                  "*"  # put the index here
                                ]
                              }
                            }
                          },
                          "condition": {
                            "compare": {
                              "ctx.payload.hits.total": alert_condition
                            }
                          },
                          "actions": {
                            "logging-action": {
                              "logging": {
                                "text": logging_result
                              }
                            }
                          }
                        }

    def finalize(self):
        for key, value in self.watcher_alert.items():
            self.output.print(key, ':', json.dumps(self.watcher_alert[key]))

class LogPointBackend(SingleTextQueryBackend):
    """Converts Sigma rule into LogPoint query"""
    identifier = "logpoint"
    active = True

    reEscape = re.compile('(["\\\\])')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = " -"
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ", "
    valueExpression = "\"%s\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    
    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | chart %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | chart %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)
    
class SplunkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "splunk"
    active = True
    index_field = "index"

    reEscape = re.compile('(["\\\\])')
    reClear = None
    andToken = " "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "\"%s\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = False
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, node):
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | stats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | stats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)

### Backends for developement purposes

class FieldnameListBackend(BaseBackend):
    """List all fieldnames from given Sigma rules for creation of a field mapping configuration."""
    identifier = "fieldlist"
    active = True
    output_class = SingleOutput

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            self.output.print("\n".join(sorted(set(list(flatten(self.generateNode(parsed.parsedSearch)))))))

    def generateANDNode(self, node):
        return [self.generateNode(val) for val in node]

    def generateORNode(self, node):
        return self.generateANDNode(node)

    def generateNOTNode(self, node):
        return self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return [self.generateNode(value) for value in node]

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        return [key]

    def generateValueNode(self, node):
        return []

# Helpers
def flatten(l):
  for i in l:
      if type(i) == list:
          yield from flatten(i)
      else:
          yield i
