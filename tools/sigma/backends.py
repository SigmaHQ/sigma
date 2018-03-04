# Output backends for sigmac
# Copyright 2016-2017 Thomas Patzke, Florian Roth, Ben de Haan, Devin Ferguson

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

class BackendOptions(dict):
    """Object contains all options that should be passed to the backend from command line (or other user interfaces)"""

    def __init__(self, options):
        """
        Receives the argparser result from the backend option paramater value list (nargs=*) and builds the dict from it. There are two option types:

        * key=value: self{key} = value
        * key: self{key} = True
        """
        if options == None:
            return
        for option in options:
            parsed = option.split("=", 1)
            try:
                self[parsed[0]] = parsed[1]
            except IndexError:
                self[parsed[0]] = True

### Output classes
class SingleOutput:
    """
    Single file output

    By default, this opens the given file or stdin and passes everything into this.
    """
    def __init__(self, filename=None):
        if type(filename) == str:
            self.fd = open(filename, "w", encoding='utf-8')
        else:
            self.fd = sys.stdout

    def print(self, *args, **kwargs):
        print(*args, file=self.fd, **kwargs)

    def close(self):
        self.fd.close()

### Generic backend base classes and mixins
class BaseBackend:
    """Base class for all backends"""
    identifier = "base"
    active = False
    index_field = None    # field name that is used to address indices
    output_class = None   # one of the above output classes
    file_list = None

    def __init__(self, sigmaconfig, backend_options=None, filename=None):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it. Further, output files are initialized by the output class defined in output_class.
        """
        super().__init__()
        if not isinstance(sigmaconfig, (sigma.config.SigmaConfiguration, None)):
            raise TypeError("SigmaConfiguration object expected")
        self.options = backend_options
        self.sigmaconfig = sigmaconfig
        self.sigmaconfig.set_backend(self)
        self.output = self.output_class(filename)

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            before = self.generateBefore(parsed)
            if before is not None:
                self.output.print(before, end="")
            self.output.print(self.generateQuery(parsed))
            after = self.generateAfter(parsed)
            if after is not None:
                self.output.print(after, end="")

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            result += self.generateAggregation(parsed.parsedAgg)
        return result

    def generateNode(self, node):
        if type(node) == sigma.parser.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.NodeSubexpression:
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

    def generateNULLValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateNotNULLValueNode(self, node):
        raise NotImplementedError("Node type not implemented for this backend")

    def generateAggregation(self, agg):
        raise NotImplementedError("Aggregations not implemented for this backend")

    def generateBefore(self, parsed):
        return ""

    def generateAfter(self, parsed):
        return ""

    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        pass

class QuoteCharMixin:
    """
    This class adds the cleanValue method that quotes and filters characters according to the configuration in
    the attributes provided by the mixin.
    """
    reEscape = None                     # match characters that must be quoted
    escapeSubst = "\\\\\g<1>"           # Substitution that is applied to characters/strings matched for escaping by reEscape
    reClear = None                      # match characters that are cleaned out completely

    def cleanValue(self, val):
        if self.reEscape:
            val = self.reEscape.sub(self.escapeSubst, val)
        if self.reClear:
            val = self.reClear.sub("", val)
        return val

class RulenameCommentMixin:
    """Prefixes each rule with the rule title."""
    prefix = "# "

    def generateBefore(self, parsed):
        if "rulecomment" in self.options:
            try:
                return "\n%s%s\n" % (self.prefix, parsed.sigmaParser.parsedyaml['title'])
            except KeyError:
                return ""

class SingleTextQueryBackend(RulenameCommentMixin, BaseBackend, QuoteCharMixin):
    """Base class for backends that generate one text-based expression from a Sigma rule"""
    identifier = "base-textquery"
    active = False
    output_class = SingleOutput

    # the following class variables define the generation and behavior of queries from a parse tree some are prefilled with default values that are quite usual
    andToken = None                     # Token used for linking expressions with logical AND
    orToken = None                      # Same for OR
    notToken = None                     # Same for NOT
    subExpression = None                # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = None               # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = None                # Character for separation of list items
    valueExpression = None              # Expression of values, %s represents value
    nullExpression = None               # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = None            # Expression of queries for not null values. %s is field name
    mapExpression = None                # Syntax for field/value conditions. First %s is key, second is value
    mapListsSpecialHandling = False     # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = None       # Syntax for field/value condititons where map value is a list

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

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

class MultiRuleOutputMixin:
    """Mixin with common for multi-rule outputs"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rulenames = set()

    def getRuleName(self, sigmaparser):
        """
        Generate a rule name from the title of the Sigma rule with following properties:

        * Spaces are replaced with -
        * Unique name by addition of a counter if generated name already in usage

        Generated names are tracked by the Mixin.
        
        """
        rulename = sigmaparser.parsedyaml["title"].replace(" ", "-")
        if rulename in self.rulenames:   # add counter if name collides
            cnt = 2
            while "%s-%d" % (rulename, cnt) in self.rulenames:
                cnt += 1
            rulename = "%s-%d" % (rulename, cnt)
        self.rulenames.add(rulename)

        return rulename

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
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s:%s"
    mapListsSpecialHandling = False

class KibanaBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into Kibana JSON Configuration files (searches only)."""
    identifier = "kibana"
    active = True
    output_class = SingleOutput

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kibanaconf = list()

    def generate(self, sigmaparser):
        rulename = self.getRuleName(sigmaparser)
        description = sigmaparser.parsedyaml.setdefault("description", "")

        columns = list()
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field)
                if type(mapped) == str:
                    columns.append(mapped)
                elif type(mapped) == list:
                    columns.extend(mapped)
                else:
                    raise TypeError("Field mapping must return string or list")
        except KeyError:    # no 'fields' attribute
            pass

        indices = sigmaparser.get_logsource().index
        if len(indices) == 0:   # fallback if no index is given
            indices = ["*"]

        for parsed in sigmaparser.condparsed:
            result = self.generateNode(parsed.parsedSearch)

            for index in indices:
                final_rulename = rulename
                if len(indices) > 1:     # add index names if rule must be replicated because of ambigiuous index patterns
                    raise NotSupportedError("Multiple target indices are not supported by Kibana")
                else:
                    title = sigmaparser.parsedyaml["title"]
                try:
                    title = self.options["prefix"] + title
                except KeyError:
                    pass

                self.kibanaconf.append({
                        "_id": final_rulename,
                        "_type": "search",
                        "_source": {
                            "title": title,
                            "description": description,
                            "hits": 0,
                            "columns": columns,
                            "sort": ["@timestamp", "desc"],
                            "version": 1,
                            "kibanaSavedObjectMeta": {
                                "searchSourceJSON": json.dumps({
                                    "index": index,
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
        self.output.print(json.dumps(self.kibanaconf, indent=2))

class XPackWatcherBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma Rule into X-Pack Watcher JSON for alerting"""
    identifier = "xpack-watcher"
    active = True
    output_class = SingleOutput

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watcher_alert = dict()
        try:
            self.output_type = self.options["output"]
        except KeyError:
            self.output_type = "curl"

        try:
            self.es = self.options["es"]
        except KeyError:
            self.es = "localhost:9200"

    def generate(self, sigmaparser):
        # get the details if this alert occurs
        rulename = self.getRuleName(sigmaparser)
        title = sigmaparser.parsedyaml.setdefault("title", "")
        description = sigmaparser.parsedyaml.setdefault("description", "")
        false_positives = sigmaparser.parsedyaml.setdefault("falsepositives", "")
        level = sigmaparser.parsedyaml.setdefault("level", "")
        # Get time frame if exists
        interval = sigmaparser.parsedyaml["detection"].setdefault("timeframe", "30m")

        # creating condition
        indices = sigmaparser.get_logsource().index

        for condition in sigmaparser.condparsed:
            result = self.generateNode(condition.parsedSearch)
            agg = {}
            alert_value_location = ""
            try:
                condition_value = int(condition.parsedAgg.condition)
                min_doc_count = {}
                if condition.parsedAgg.cond_op == ">":
                    alert_condition = { "gt": condition_value }
                    min_doc_count = { "min_doc_count": condition_value + 1 }
                    order = "desc"
                elif condition.parsedAgg.cond_op == ">=":
                    alert_condition = { "gte": condition_value }
                    min_doc_count = { "min_doc_count": condition_value }
                    order = "desc"
                elif condition.parsedAgg.cond_op == "<":
                    alert_condition = { "lt": condition_value }
                    order = "asc"
                elif condition.parsedAgg.cond_op == "<=":
                    alert_condition = { "lte": condition_value }
                    order = "asc"
                else:
                    alert_condition = {"not_eq": 0}

                agg_iter = list()
                if condition.parsedAgg.aggfield is not None:    # e.g. ... count(aggfield) ...
                    agg = {
                            "aggs": {
                                "agg": {
                                    "terms": {
                                        "field": condition.parsedAgg.aggfield + ".keyword",
                                        "size": 10,
                                        "order": {
                                            "_count": order
                                            },
                                        **min_doc_count
                                        },
                                    **agg
                                    }
                                }
                            }
                    alert_value_location = "agg.buckets.0."
                    agg_iter.append("agg.buckets")
                if condition.parsedAgg.groupfield is not None:    # e.g. ... by groupfield ...
                    agg = {
                            "aggs": {
                                "by": {
                                    "terms": {
                                        "field": condition.parsedAgg.groupfield + ".keyword",
                                        "size": 10,
                                        "order": {
                                            "_count": order
                                            },
                                        **min_doc_count
                                        },
                                    **agg
                                    }
                                }
                            }
                    alert_value_location = "by.buckets.0." + alert_value_location
                    agg_iter.append("by.buckets")
            except KeyError:
                alert_condition = {"not_eq": 0}
            except AttributeError:
                alert_condition = {"not_eq": 0}

            if agg != {}:
                alert_value_location = "ctx.payload.aggregations." + alert_value_location + "doc_count"
                agg_iter[0] = "aggregations." + agg_iter[0]
                action_body = "Hits:\n"
                action_body += "\n".join([
                    ("{{#%s}}\n" + (2 * i * "-") + " {{key}} {{doc_count}}\n") % (agg_item) for i, agg_item in enumerate(agg_iter)
                    ])
                action_body += "\n".join([
                    "{{/%s}}\n" % agg_item for agg_item in reversed(agg_iter)
                    ])
            else:
                alert_value_location = "ctx.payload.hits.total"
                action_body = "Hits:\n{{#ctx.payload.hits.hits}}"
                try:    # extract fields if these are given in rule
                    fields = sigmaparser.parsedyaml['fields']
                    max_field_len = max([len(field) for field in fields])
                    action_body += "Hit on {{_source.@timestamp}}:\n" + "\n".join([
                        ("%" + str(max_field_len) + "s = {{_source.%s}}") % (field, field) for field in fields
                        ]) + (80 * "=") + "\n"
                except KeyError:    # no fields given, extract all hits
                    action_body += "{{_source}}\n"
                    action_body += (80 * "=") + "\n"
                action_body += "{{/ctx.payload.hits.hits}}"

            # Building the action
            action_subject = "Sigma Rule '%s'" % title
            try:    # mail notification if mail address is given
                email = self.options['mail']
                action = {
                        "send_email": {
                            "email": {
                                "to": email,
                                "subject": action_subject,
                                "body": action_body,
                                "attachments": {
                                    "data.json": {
                                        "data": {
                                            "format": "json"
                                            }
                                        }
                                    }
                                }
                            }
                        }
            except KeyError:    # no mail address given, generate log action
                action = {
                        "logging-action": {
                            "logging": {
                                "text": action_subject + ": " + action_body
                                }
                            }
                        }

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
                                      },
                                      **agg
                                    },
                                    "indices": indices
                                  }
                                }
                              },
                              "condition": {
                                  "compare": {
                                  alert_value_location: alert_condition
                                }
                              },
                              "actions": { **action }
                            }

    def finalize(self):
        for rulename, rule in self.watcher_alert.items():
            if self.output_type == "plain":     # output request line + body
                self.output.print("PUT _xpack/watcher/watch/%s\n%s\n" % (rulename, json.dumps(rule, indent=2)))
            elif self.output_type == "curl":      # output curl command line
                self.output.print("curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- %s/_xpack/watcher/watch/%s <<EOF\n%s\nEOF" % (self.es, rulename, json.dumps(rule, indent=2)))
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)

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
    nullExpression = "-%s=*"
    notNullExpression = "%s=*"
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"
    
    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.SigmaAggregationParser.AGGFUNC_NEAR:
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
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, key, value):
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            return " | stats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | stats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)

class GrepBackend(BaseBackend, QuoteCharMixin):
    """Generates Perl compatible regular expressions and puts 'grep -P' around it"""
    identifier = "grep"
    active = True
    output_class = SingleOutput

    reEscape = re.compile("([\\|()\[\]{}.^$])")

    def generateQuery(self, parsed):
        return "grep -P '^%s'" % self.generateNode(parsed.parsedSearch)

    def cleanValue(self, val):
        val = super().cleanValue(val)
        return re.sub("\\*", ".*", val)

    def generateORNode(self, node):
        return "(?:%s)" % "|".join([".*" + self.generateNode(val) for val in node])

    def generateANDNode(self, node):
        return "".join(["(?=.*%s)" % self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return "(?!.*%s)" % self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return "(?:.*%s)" % self.generateNode(node.items)

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.generateORNode(node)

    def generateMapItemNode(self, node):
        key, value = node
        return self.generateNode(value)

    def generateValueNode(self, node):
        return self.cleanValue(str(node))

### Backends for developement purposes

class FieldnameListBackend(BaseBackend):
    """List all fieldnames from given Sigma rules for creation of a field mapping configuration."""
    identifier = "fieldlist"
    active = True
    output_class = SingleOutput

    def generateQuery(self, parsed):
        return "\n".join(sorted(set(list(flatten(self.generateNode(parsed.parsedSearch))))))

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

# Exceptions
class BackendError(Exception):
    """Base exception for backend-specific errors."""
    pass

class NotSupportedError(BackendError):
    """Exception is raised if some output is required that is not supported by the target language."""
    pass
