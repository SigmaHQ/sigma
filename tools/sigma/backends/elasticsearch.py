# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Devin Ferguson, Julien Bachmann

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

import json
import re
import sys

import sigma
import yaml
from .base import BaseBackend, SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from .exceptions import NotSupportedError

class ElasticsearchWildcardHandlingMixin(object):
    """
    Determine field mapping to keyword subfields depending on existence of wildcards in search values. Further,
    provide configurability with backend parameters.
    """
    options = SingleTextQueryBackend.options + (
            ("keyword_field", "keyword", "Keyword sub-field name", None),
            ("keyword_blacklist", None, "Fields that don't have a keyword subfield", None)
            )
    reContainsWildcard = re.compile("(?<!\\\\)[*?]").search

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.matchKeyword = True
        try:
            self.blacklist = self.keyword_blacklist.split(",")
        except AttributeError:
            self.blacklist = list()

    def containsWildcard(self, value):
        """Determine if value contains wildcard."""
        if type(value) == str:
            return self.reContainsWildcard(value)
        else:
            return False

    def fieldNameMapping(self, fieldname, value):
        """
        Determine if values contain wildcards. If yes, match on keyword field else on analyzed one.
        Decide if field value should be quoted based on the field name decision and store it in object property.
        """
        if fieldname not in self.blacklist and (
                type(value) == list and any(map(self.containsWildcard, value)) \
                or self.containsWildcard(value)
                ):
            self.matchKeyword = True
            return fieldname + "." + self.keyword_field
        else:
            self.matchKeyword = False
            return fieldname

class ElasticsearchQuerystringBackend(ElasticsearchWildcardHandlingMixin, SingleTextQueryBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([\s+\\-=!(){}\\[\\]^\"~:/]|(?<!\\\\)\\\\(?![*?\\\\])|\\\\u|&&|\\|\\|)")
    reClear = re.compile("[<>]")
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s:%s"
    mapListsSpecialHandling = False

    def generateValueNode(self, node):
        result = super().generateValueNode(node)
        if result == "" or result.isspace():
            return '""'
        else:
            if self.matchKeyword:   # don't quote search value on keyword field
                return result
            else:
                return "\"%s\"" % result

class ElasticsearchDSLBackend(RulenameCommentMixin, ElasticsearchWildcardHandlingMixin, BaseBackend):
    """ElasticSearch DSL backend"""
    identifier = 'es-dsl'
    active = True
    options = RulenameCommentMixin.options + ElasticsearchWildcardHandlingMixin.options + (
        ("es", "http://localhost:9200", "Host and port of Elasticsearch instance", None),
        ("output", "import", "Output format: import = JSON search request, curl = Shell script that do the search queries via curl", "output_type"),
    )
    interval = None
    title = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queries = []

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        self.title = sigmaparser.parsedyaml["title"]
        self.indices = sigmaparser.get_logsource().index
        if len(self.indices) == 0:
            self.indices = None

        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

        for parsed in sigmaparser.condparsed:
            self.generateBefore(parsed)
            self.generateQuery(parsed)
            self.generateAfter(parsed)

    def generateQuery(self, parsed):
        self.queries[-1]['query']['constant_score']['filter'] = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            self.generateAggregation(parsed.parsedAgg)
        # if parsed.parsedAgg:
        #     fields += self.generateAggregation(parsed.parsedAgg)
        # self.fields.update(fields)

    def generateANDNode(self, node):
        andNode = {'bool': {'must': []}}
        for val in node:
            andNode['bool']['must'].append(self.generateNode(val))
        return andNode

    def generateORNode(self, node):
        orNode = {'bool': {'should': []}}
        for val in node:
            orNode['bool']['should'].append(self.generateNode(val))
        return orNode

    def generateNOTNode(self, node):
        notNode = {'bool': {'must_not': []}}
        for val in node:
            notNode['bool']['must_not'].append(self.generateNode(val))
        return notNode

    def generateSubexpressionNode(self, node):
        return self.generateNode(node.items)

    def generateListNode(self, node):
        raise NotImplementedError("%s : (%s) Node type not implemented for this backend"%(self.title, 'generateListNode'))

    def cleanValue(self, value):
        """
        Remove Sigma quoting from value. Currently, this appears only in one case: \\\\*
        """
        return value.replace("\\\\*", "\\*")

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        if type(value) is list:
            res = {'bool': {'should': []}}
            for v in value:
                key_mapped = self.fieldNameMapping(key, v)
                if self.matchKeyword:   # searches against keyowrd fields are wildcard searches, phrases otherwise
                    queryType = 'wildcard'
                else:
                    queryType = 'match_phrase'

                res['bool']['should'].append({queryType: {key_mapped: self.cleanValue(str(v))}})
            return res
        else:
            key_mapped = self.fieldNameMapping(key, value)
            if self.matchKeyword:   # searches against keyowrd fields are wildcard searches, phrases otherwise
                queryType = 'wildcard'
            else:
                queryType = 'match_phrase'
            return {queryType: {key_mapped: self.cleanValue(str(value))}}

    def generateValueNode(self, node):
        return {'multi_match': {'query': node, 'fields': [], 'type': 'phrase'}}

    def generateNULLValueNode(self, node):
        return {'bool': {'must_not': {'exists': {'field': node.item}}}}

    def generateNotNULLValueNode(self, node):
        return {'exists': {'field': node.item}}

    def generateAggregation(self, agg):
        if agg:
            if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT:
                if agg.groupfield is not None:
                    self.queries[-1]['aggs'] = {
                        '%s_count'%(agg.groupfield or ""): {
                            'terms': {
                                'field': '%s'%(agg.groupfield or "")
                            },
                            'aggs': {
                                'limit': {
                                    'bucket_selector': {
                                        'buckets_path': {
                                            'count': '_count'
                                        },
                                        'script': 'params.count %s %s'%(agg.cond_op, agg.condition)
                                    }
                                }
                            }
                        }
                    }
            else:
                for name, idx in agg.aggfuncmap.items():
                    if idx == agg.aggfunc:
                        funcname = name
                        break
                raise NotImplementedError("%s : The '%s' aggregation operator is not yet implemented for this backend"%(self.title, funcname))

    def generateBefore(self, parsed):
        self.queries.append({'query': {'constant_score': {'filter': {}}}})

    def generateAfter(self, parsed):
        dateField = 'date'
        if self.sigmaconfig.config and 'dateField' in self.sigmaconfig.config:
            dateField = self.sigmaconfig.config['dateField']
        if self.interval:
            if 'bool' not in self.queries[-1]['query']['constant_score']['filter']:
                self.queries[-1]['query']['constant_score']['filter'] = {'bool': {'must': []}}
            if 'must' not in self.queries[-1]['query']['constant_score']['filter']['bool']:
                self.queries[-1]['query']['constant_score']['filter']['bool']['must'] = []

            self.queries[-1]['query']['constant_score']['filter']['bool']['must'].append({'range': {dateField: {'gte': 'now-%s'%self.interval}}})

    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        index = ''
        if self.indices is not None and len(self.indices) == 1:
            index = '%s/'%self.indices[0]

        if self.output_type == 'curl':
            for query in self.queries:
                return "\curl -XGET '%s/%s_search?pretty' -H 'Content-Type: application/json' -d'%s'" % (self.es, index, json.dumps(query, indent=2))
        else:
            if len(self.queries) == 1:
                return json.dumps(self.queries[0], indent=2)
            else:
                return json.dumps(self.queries, indent=2)

class KibanaBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into Kibana JSON Configuration files (searches only)."""
    identifier = "kibana"
    active = True
    options = ElasticsearchQuerystringBackend.options + (
            ("output", "import", "Output format: import = JSON file manually imported in Kibana, curl = Shell script that imports queries in Kibana via curl (jq is additionally required)", "output_type"),
            ("es", "localhost:9200", "Host and port of Elasticsearch instance", None),
            ("index", ".kibana", "Kibana index", None),
            ("prefix", "Sigma: ", "Title prefix of Sigma queries", None),
            )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kibanaconf = list()
        self.indexsearch = set()

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
                    title = self.prefix + sigmaparser.parsedyaml["title"]

                self.indexsearch.add(
                        "export {indexvar}=$(curl -s '{es}/{index}/_search?q=index-pattern.title:{indexpattern}' | jq -r '.hits.hits[0]._id | ltrimstr(\"index-pattern:\")')".format(
                            es=self.es,
                            index=self.index,
                            indexpattern=index.replace("*", "\\*"),
                            indexvar=self.index_variable_name(index)
                            )
                        )
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
                                "searchSourceJSON": {
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
                            }
                        }
                    })

    def finalize(self):
        if self.output_type == "import":        # output format that can be imported via Kibana UI
            for item in self.kibanaconf:    # JSONize kibanaSavedObjectMeta.searchSourceJSON
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.dumps(item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'])
            return json.dumps(self.kibanaconf, indent=2)
        elif self.output_type == "curl":
            for item in self.indexsearch:
                return item
            for item in self.kibanaconf:
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON']['index'] = "$" + self.index_variable_name(item['_source']['kibanaSavedObjectMeta']['searchSourceJSON']['index'])   # replace index pattern with reference to variable that will contain Kibana index UUID at script runtime
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.dumps(item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'])     # Convert it to JSON string as expected by Kibana
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'] = item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'].replace("\\", "\\\\")      # Add further escaping for escaped quotes for shell
                return "curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- '{es}/{index}/doc/{doc_id}' <<EOF\n{doc}\nEOF".format(
                        es=self.es,
                        index=self.index,
                        doc_id="search:" + item['_id'],
                        doc=json.dumps({
                            "type": "search",
                            "search": item['_source']
                            }, indent=2)
                        )
        else:
            raise NotImplementedError("Output type '%s' not supported" % self.output_type)

    def index_variable_name(self, index):
        return "index_" + index.replace("-", "__").replace("*", "X")

class XPackWatcherBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma Rule into X-Pack Watcher JSON for alerting"""
    identifier = "xpack-watcher"
    active = True
    options = ElasticsearchQuerystringBackend.options + (
            ("output", "curl", "Output format: curl = Shell script that imports queries in Watcher index with curl", "output_type"),
            ("es", "localhost:9200", "Host and port of Elasticsearch instance", None),
            ("mail", None, "Mail address for Watcher notification (only logging if not set)", None),
            )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watcher_alert = dict()

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
                email = self.mail
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
        result = ""
        for rulename, rule in self.watcher_alert.items():
            if self.output_type == "plain":     # output request line + body
                result += "PUT _xpack/watcher/watch/%s\n%s\n" % (rulename, json.dumps(rule, indent=2))
            elif self.output_type == "curl":      # output curl command line
                result += "curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- %s/_xpack/watcher/watch/%s <<EOF\n%s\nEOF\n" % (self.es, rulename, json.dumps(rule, indent=2))
            elif self.output_type == "json":    # output compressed watcher json, one per line
                result += json.dumps(rule) + "\n"
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)
        return result

class ElastalertBackend(MultiRuleOutputMixin, ElasticsearchQuerystringBackend):
    """Elastalert backend"""
    identifier = 'elastalert'
    active = True
    supported_alert_methods = {'email', 'http_post'}

    options = ElasticsearchQuerystringBackend.options + (
        ("alert_methods", "", "Alert method(s) to use when the rule triggers, comma separated. Supported: " + ', '.join(supported_alert_methods), None),

        # Options for HTTP POST alerting
        ("http_post_url", None, "Webhook URL used for HTTP POST alert notification", None),
        ("http_post_include_rule_metadata", None, "Indicates if metadata about the rule which triggered should be included in the paylod of the HTTP POST alert notification", None),

        # Options for email alerting
        ("emails", None, "Email addresses for Elastalert notification, if you want to alert several email addresses put them coma separated", None),
        ("smtp_host", None, "SMTP server address", None),
        ("from_addr", None, "Email sender address", None),
        ("smtp_auth_file", None, "Local path with login info", None),

        # Generic alerting options
        ("realert_time", "0m", "Ignore repeating alerts for a period of time", None),
        ("expo_realert_time", "60m", "This option causes the value of realert to exponentially increase while alerts continue to fire", None)
    )
    interval = None
    title = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.elastalert_alerts = dict()
        self.fields = []

    def generate(self, sigmaparser):
        rulename = self.getRuleName(sigmaparser)
        title = sigmaparser.parsedyaml.setdefault("title", "")
        description = sigmaparser.parsedyaml.setdefault("description", "")
        false_positives = sigmaparser.parsedyaml.setdefault("falsepositives", "")
        level = sigmaparser.parsedyaml.setdefault("level", "")
        rule_tag = sigmaparser.parsedyaml.setdefault("tags", ["NOT-DEF"])
        # Get time frame if exists
        interval = self.generateTimeframe(sigmaparser.parsedyaml["detection"].setdefault("timeframe", "30m"))
        # creating condition
        index = sigmaparser.get_logsource().index
        if len(index) == 0:   # fallback if no index is given
            index = "logstash-*"
        elif len(index) > 0:
            index = index[0]
        #Init a rule number cpt in case there are several elastalert rules generated fron one Sigma rule
        rule_number = 0
        for parsed in sigmaparser.condparsed:
            #Static data
            rule_object = {
                "name": rulename + "_" + str(rule_number),
                "description": description,
                "index": index,
                "priority": self.convertLevel(level),
                "realert": self.generateTimeframe(self.realert_time),
                #"exponential_realert": self.generateTimeframe(self.expo_realert_time)
            }
            rule_object['filter'] = self.generateQuery(parsed)

            #Handle aggregation
            if parsed.parsedAgg:
                if parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MIN or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MAX or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_AVG or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_SUM:
                    if parsed.parsedAgg.groupfield is not None:
                        rule_object['query_key'] = parsed.parsedAgg.groupfield + ".keyword"
                    rule_object['type'] = "metric_aggregation"
                    rule_object['buffer_time'] = interval
                    rule_object['doc_type'] = "doc"

                    if parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT:
                        rule_object['metric_agg_type'] = "cardinality"
                    else:
                        rule_object['metric_agg_type'] = parsed.parsedAgg.aggfunc_notrans

                    if parsed.parsedAgg.aggfield:
                        rule_object['metric_agg_key'] = parsed.parsedAgg.aggfield + ".keyword"
                    else:
                        rule_object['metric_agg_key'] = "_id"

                    condition_value = int(parsed.parsedAgg.condition)
                    if parsed.parsedAgg.cond_op == ">":
                        rule_object['max_threshold'] = condition_value
                    elif parsed.parsedAgg.cond_op == ">=":
                        rule_object['max_threshold'] = condition_value - 1
                    elif parsed.parsedAgg.cond_op == "<":
                        rule_object['min_threshold'] = condition_value
                    elif parsed.parsedAgg.cond_op == "<=":
                        rule_object['min_threshold'] = condition_value - 1
                    else:
                        rule_object['max_threshold'] = condition_value - 1
                        rule_object['min_threshold'] = condition_value + 1
            else:
                rule_object['type'] = "any"

            #Handle alert action
            rule_object['alert'] = []
            alert_methods = self.alert_methods.split(',')
            if 'email' in alert_methods:
                rule_object['alert'].append('email')
                rule_object['email'] = []
                for address in self.emails.split(','):
                    rule_object['email'].append(address)
                if self.smtp_host:
                    rule_object['smtp_host'] = self.smtp_host
                if self.from_addr:
                    rule_object['from_addr'] = self.from_addr
                if self.smtp_auth_file:
                    rule_object['smtp_auth_file'] = self.smtp_auth_file
            if 'http_post' in alert_methods:
                if self.http_post_url is None:
                    print('Warning: the Elastalert HTTP POST method is selected but no URL has been provided. This alert method will be ignored', file=sys.stderr)
                else:
                    rule_object['alert'].append('post')
                    rule_object['http_post_url'] = self.http_post_url
                    if self.http_post_include_rule_metadata:
                        rule_object['http_post_static_payload'] = {
                            'sigma_rule_metadata': {
                                'title': title,
                                'description': description,
                                'level': level,
                                'tags': rule_tag
                            }
                        }
            #If alert is not define put debug as default
            if len(rule_object['alert']) == 0:
                rule_object['alert'].append('debug')

            #Increment rule number
            rule_number += 1
            self.elastalert_alerts[rule_object['name']] = rule_object
            #Clear fields
            self.fields = []

    def generateQuery(self, parsed):
        #Generate ES QS Query
        return [{ 'query' : { 'query_string' : { 'query' : super().generateQuery(parsed) } } }]

    def generateNode(self, node):
        #Save fields for adding them in query_key
        #if type(node) == sigma.parser.NodeSubexpression:
        #    for k,v in node.items.items:
        #        self.fields.append(k)
        return super().generateNode(node)

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

    def generateAggregation(self, agg):
        if agg:
            if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT or agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MIN or agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MAX or agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_AVG or agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_SUM:
                return ""
            else:
                for name, idx in agg.aggfuncmap.items():
                    if idx == agg.aggfunc:
                        funcname = name
                        break
                raise NotImplementedError("%s : The '%s' aggregation operator is not yet implemented for this backend"%(self.title, funcname)) 

    def convertLevel(self, level):
    	return {
        	'critical': 1,
        	'high': 2,
        	'medium': 3,
        	'low': 4
    	}.get(level, 2)

    def finalize(self):
        result = ""
        for rulename, rule in self.elastalert_alerts.items():
            result += yaml.dump(rule, default_flow_style=False)
            result += '\n'
        return result
