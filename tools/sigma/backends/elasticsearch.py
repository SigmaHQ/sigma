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
import sigma
from .base import BaseBackend, SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from .output import SingleOutput
from .exceptions import NotSupportedError

class ElasticsearchQuerystringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([+\\-=!(){}\\[\\]^\"~:/]|\\\\(?![*?])|\\\\u|&&|\\|\\|)")
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

class ElasticsearchDSLBackend(RulenameCommentMixin, BaseBackend):
    """ElasticSearch DSL backend"""
    identifier = 'es-dsl'
    active = True
    output_class = SingleOutput
    options = (
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

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) not in (str, int, list):
            raise TypeError("Map values must be strings, numbers or lists, not " + str(type(value)))
        if type(value) is list:
            res = {'bool': {'should': []}}
            for v in value:
                res['bool']['should'].append({'match_phrase': {key: v}})
            return res
        else:
            return {'match_phrase': {key: value}}

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
                        '%s_count'%agg.groupfield: {
                            'terms': {
                                'field': '%s'%agg.groupfield
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
                self.output.print("\curl -XGET '%s/%s_search?pretty' -H 'Content-Type: application/json' -d'"%(self.es, index))
                self.output.print(json.dumps(query, indent=2))
                self.output.print("'")
        else:
            if len(self.queries) == 1:
                self.output.print(json.dumps(self.queries[0], indent=2))
            else:
                self.output.print(json.dumps(self.queries, indent=2))

class KibanaBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into Kibana JSON Configuration files (searches only)."""
    identifier = "kibana"
    active = True
    output_class = SingleOutput
    options = (
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
            self.output.print(json.dumps(self.kibanaconf, indent=2))
        elif self.output_type == "curl":
            for item in self.indexsearch:
                self.output.print(item)
            for item in self.kibanaconf:
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON']['index'] = "$" + self.index_variable_name(item['_source']['kibanaSavedObjectMeta']['searchSourceJSON']['index'])   # replace index pattern with reference to variable that will contain Kibana index UUID at script runtime
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.dumps(item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'])     # Convert it to JSON string as expected by Kibana
                item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'] = item['_source']['kibanaSavedObjectMeta']['searchSourceJSON'].replace("\\", "\\\\")      # Add further escaping for escaped quotes for shell
                self.output.print(
                        "curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- '{es}/{index}/doc/{doc_id}' <<EOF\n{doc}\nEOF".format(
                            es=self.es,
                            index=self.index,
                            doc_id="search:" + item['_id'],
                            doc=json.dumps({
                                "type": "search",
                                "search": item['_source']
                                }, indent=2)
                            )
                        )
        else:
            raise NotImplementedError("Output type '%s' not supported" % self.output_type)

    def index_variable_name(self, index):
        return "index_" + index.replace("-", "__").replace("*", "X")

class XPackWatcherBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma Rule into X-Pack Watcher JSON for alerting"""
    identifier = "xpack-watcher"
    active = True
    output_class = SingleOutput
    options = (
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
        for rulename, rule in self.watcher_alert.items():
            if self.output_type == "plain":     # output request line + body
                self.output.print("PUT _xpack/watcher/watch/%s\n%s\n" % (rulename, json.dumps(rule, indent=2)))
            elif self.output_type == "curl":      # output curl command line
                self.output.print("curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- %s/_xpack/watcher/watch/%s <<EOF\n%s\nEOF" % (self.es, rulename, json.dumps(rule, indent=2)))
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)
