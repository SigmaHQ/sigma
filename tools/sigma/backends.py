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
    options = tuple()     # a list of tuples with following elements: option name, default value, help text, target attribute name (option name if None)

    def __init__(self, sigmaconfig, backend_options=None, filename=None):
        """
        Initialize backend. This gets a sigmaconfig object, which is notified about the used backend class by
        passing the object instance to it. Further, output files are initialized by the output class defined in output_class.
        """
        super().__init__()
        if not isinstance(sigmaconfig, (sigma.config.SigmaConfiguration, None)):
            raise TypeError("SigmaConfiguration object expected")
        self.backend_options = backend_options
        self.sigmaconfig = sigmaconfig
        self.sigmaconfig.set_backend(self)
        self.output = self.output_class(filename)

        # Parse options
        for option, default_value, _, target in self.options:
            if target is None:
                target = option
            setattr(self, target, self.backend_options.setdefault(option, default_value))

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            if before is not None:
                self.output.print(before, end="")
            if query is not None:
                self.output.print(query)
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
    options = (
            ("rulecomment", False, "Prefix generated query with comment containing title", None),
            )

    def generateBefore(self, parsed):
        if self.rulecomment:
            try:
                return "%s%s\n" % (self.prefix, parsed.sigmaParser.parsedyaml['title'])
            except KeyError:
                return ""

    def generateAfter(self, parsed):
        if self.rulecomment:
            return "\n"

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
            if agg.aggfunc == sigma.parser.SigmaAggregationParser.AGGFUNC_COUNT:
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
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return self.notToken + generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

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
        rulename = sigmaparser.parsedyaml["title"].replace(" ", "-").replace("(", "").replace(")", "")
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

# Graylog reserved characters in search && || : \ / + - ! ( ) { } [ ] ^ " ~ * ?
# Modified from Elasticsearch backend reserved character at https://www.elastic.co/guide/en/elasticsearch/reference/2.1/query-dsl-query-string-query.html#_reserved_characters
# Elasticsearch characters + - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /

class GraylogQuerystringBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Graylog query string. Only searches, no aggregations."""     
    identifier = "graylog"
    active = True

    reEscape = re.compile("([+\\-!(){}\\[\\]^\"~:/]|\\\\(?![*?])|&&|\\|\\|)")
    reClear = None
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

class LogPointBackend(SingleTextQueryBackend):
    """Converts Sigma rule into LogPoint query"""
    identifier = "logpoint"
    active = True

    reEscape = re.compile('("|\\\\(?![*?]))')
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

    reEscape = re.compile('("|\\\\(?![*?]))')
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

class WindowsDefenderATPBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Windows Defender ATP Hunting Queries."""
    identifier = "wdatp"
    active = True

    reEscape = re.compile('("|\\\\(?![*?]))')
    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isnull(%s)"
    notNullExpression = "isnotnull(%s)"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.fieldMappings = {       # mapping between Sigma and ATP field names
                # Supported values:
                # (field name mapping, value mapping): distinct mappings for field name and value, may be a string (direct mapping) or function maps name/value to ATP target value
                # (mapping function,): receives field name and value as parameter, return list of 2 element tuples (destination field name and value)
                # (replacement, ): Replaces field occurrence with static string
                "AccountName"               : (self.id_mapping, self.default_value_mapping),
                "CommandLine"               : ("ProcessCommandLine", self.default_value_mapping),
                "ComputerName"              : (self.id_mapping, self.default_value_mapping),
                "DestinationHostname"       : ("RemoteUrl", self.default_value_mapping),
                "DestinationIp"             : ("RemoteIP", self.default_value_mapping),
                "DestinationIsIpv6"         : ("RemoteIP has \":\"", ),
                "DestinationPort"           : ("RemotePort", self.default_value_mapping),
                "Details"                   : ("RegistryValueData", self.default_value_mapping),
                "EventType"                 : ("ActionType", self.default_value_mapping),
                "Image"                     : ("FolderPath", self.default_value_mapping),
                "ImageLoaded"               : ("FolderPath", self.default_value_mapping),
                "LogonType"                 : (self.id_mapping, self.logontype_mapping),
                "NewProcessName"            : ("FolderPath", self.default_value_mapping),
                "ObjectValueName"           : ("RegistryValueName", self.default_value_mapping),
                "ParentImage"               : ("InitiatingProcessFolderPath", self.default_value_mapping),
                "SourceImage"               : ("InitiatingProcessFolderPath", self.default_value_mapping),
                "TargetFilename"            : ("FolderPath", self.default_value_mapping),
                "TargetImage"               : ("FolderPath", self.default_value_mapping),
                "TargetObject"              : ("RegistryKey", self.default_value_mapping),
                "User"                      : (self.decompose_user, ),
                }

    def id_mapping(self, src):
        """Identity mapping, source == target field name"""
        return src

    def default_value_mapping(self, val):
        op = "=="
        if "*" in val[1:-1]:     # value contains * inside string - use regex match
            op = "matches regex"
            val = re.sub('([".^$]|\\\\(?![*?]))', '\\\\\g<1>', val)
            val = re.sub('\\*', '.*', val)
            val = re.sub('\\?', '.', val)
        else:                           # value possibly only starts and/or ends with *, use prefix/postfix match
            if val.endswith("*") and val.startswith("*"):
                op = "contains"
                val = self.cleanValue(val[1:-1])
            elif val.endswith("*"):
                op = "startswith"
                val = self.cleanValue(val[:-1])
            elif val.startswith("*"):
                op = "endswith"
                val = self.cleanValue(val[1:])

        return "%s \"%s\"" % (op, val)

    def logontype_mapping(self, src):
        """Value mapping for logon events to reduced ATP LogonType set"""
        logontype_mapping = {
                2: "Interactive",
                3: "Network",
                4: "Batch",
                5: "Service",
                7: "Interactive",   # unsure
                8: "Network",
                9: "Interactive",   # unsure
                10: "Remote interactive (RDP) logons",  # really the value?
                11: "Interactive"
                }
        try:
            return logontype_mapping[int(src)]
        except KeyError:
            raise NotSupportedError("Logon type %d unknown and can't be mapped" % src)

    def decompose_user(self, src_field, src_value):
        """Decompose domain\\user User field of Sysmon events into ATP InitiatingProcessAccountDomain and InititatingProcessAccountName."""
        reUser = re.compile("^(.*?)\\\\(.*)$")
        m = reUser.match(src_value)
        if m:
            domain, user = m.groups()
            return (("InitiatingProcessAccountDomain", domain), ("InititatingProcessAccountName", user))
        else:   # assume only user name is given if backslash is missing
            return (("InititatingProcessAccountName", src_value),)

    def generate(self, sigmaparser):
        self.table = None
        try:
            self.product = sigmaparser.parsedyaml['logsource']['product']
            self.service = sigmaparser.parsedyaml['logsource']['service']
        except KeyError:
            self.product = None
            self.service = None

        super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.table is None:
            raise NotSupportedError("No WDATP table could be determined from Sigma rule")
        return "%s | where " % self.table

    def generateMapItemNode(self, node):
        """
        ATP queries refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        if type(value) == list:         # handle map items with values list like multiple OR-chained conditions
            return self.generateORNode(
                    [(key, v) for v in value]
                    )
        elif key == "EventID":            # EventIDs are not reflected in condition but in table selection
            if self.product == "windows":
                if self.service == "sysmon" and value == 1 \
                    or self.service == "security" and value == 4688:    # Process Execution
                    self.table = "ProcessCreationEvents"
                    return None
                elif self.service == "sysmon" and value == 3:      # Network Connection
                    self.table = "NetworkCommunicationEvents"
                    return None
                elif self.service == "sysmon" and value == 7:      # Image Load
                    self.table = "ImageLoadEvents"
                    return None
                elif self.service == "sysmon" and value == 8:      # Create Remote Thread
                    self.table = "MiscEvents"
                    return "ActionType == \"CreateRemoteThread\""
                elif self.service == "sysmon" and value == 11:     # File Creation
                    self.table = "FileCreationEvents"
                    return None
                elif self.service == "sysmon" and value == 13 \
                    or self.service == "security" and value == 4657:    # Set Registry Value
                    self.table = "RegistryEvents"
                    return "ActionType == \"SetValue\""
                elif self.service == "security" and value == 4624:
                    self.table = "LogonEvents"
                    return None
        elif type(value) in (str, int):     # default value processing
            try:
                mapping = self.fieldMappings[key]
            except KeyError:
                raise NotSupportedError("No mapping defined for field '%s'" % key)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    conds = mapping(key, value)
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, value)]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(val))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

        return super().generateMapItemNode(node)

class SplunkXMLBackend(SingleTextQueryBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into XML used for Splunk Dashboard Panels"""
    identifier = "splunkxml"
    active = True
    index_field = "index"


    panel_pre = "<row><panel><title>"
    panel_inf = "</title><table><search><query>"
    panel_suf = "</query><earliest>$field1.earliest$</earliest><latest>$field1.latest$</latest><sampleRatio>1</sampleRatio>" \
                "</search><option name=\"count\">20</option><option name=\"dataOverlayMode\">none</option><option name=\"" \
                "drilldown\">row</option><option name=\"percentagesRow\">false</option><option name=\"refresh.display\">" \
                "progressbar</option><option name=\"rowNumbers\">false</option><option name=\"totalsRow\">false</option>" \
                "<option name=\"wrap\">true</option></table></panel></row>"
    dash_pre = "<form><label>MyDashboard</label><fieldset submitButton=\"false\"><input type=\"time\" token=\"field1\">" \
               "<label></label><default><earliest>-24h@h</earliest><latest>now</latest></default></input></fieldset>"
    dash_suf = "</form>"
    queries = dash_pre


    reEscape = re.compile('("|\\\\(?![*?]))')
    reClear = SplunkBackend.reClear
    andToken = SplunkBackend.andToken
    orToken = SplunkBackend.orToken
    notToken = SplunkBackend.notToken
    subExpression = SplunkBackend.subExpression
    listExpression = SplunkBackend.listExpression
    listSeparator = SplunkBackend.listSeparator
    valueExpression = SplunkBackend.valueExpression
    nullExpression = SplunkBackend.nullExpression
    notNullExpression = SplunkBackend.notNullExpression
    mapExpression = SplunkBackend.mapExpression
    mapListsSpecialHandling = SplunkBackend.mapListsSpecialHandling
    mapListValueExpression = SplunkBackend.mapListValueExpression

    def generateMapItemListNode(self, key, value):
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.SigmaAggregationParser.AGGFUNC_NEAR:
            return ""
        if agg.groupfield == None:
            return " | stats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.cond_op, agg.condition)
        else:
            return " | stats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield, agg.groupfield, agg.cond_op, agg.condition)


    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            if query is not None:
                self.queries += self.panel_pre
                self.queries += self.getRuleName(sigmaparser)
                self.queries += self.panel_inf
                query = query.replace("<", "&lt;")
                query = query.replace(">", "&gt;")
                self.queries += query
                self.queries += self.panel_suf

    def finalize(self):
        self.queries += self.dash_suf
        self.output.print(self.queries)

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields = set()

    def generateQuery(self, parsed):
        fields = list(flatten(self.generateNode(parsed.parsedSearch)))
        if parsed.parsedAgg:
            fields += self.generateAggregation(parsed.parsedAgg)
        self.fields.update(fields)

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

    def generateNULLValueNode(self, node):
        return [node.item]

    def generateNotNULLValueNode(self, node):
        return [node.item]

    def generateAggregation(self, agg):
        fields = list()
        if agg.groupfield is not None:
            fields.append(agg.groupfield)
        if agg.aggfield is not None:
            fields.append(agg.aggfield)
        return fields

    def finalize(self):
        self.output.print("\n".join(sorted(self.fields)))

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

class PartialMatchError(Exception):
    pass

class FullMatchError(Exception):
    pass    

class ArcSightBackend(SingleTextQueryBackend):
    """Converts Sigma rule into ArcSight saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "arcsight"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = " NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "\"%s\""
    containsExpression = "%s CONTAINS %s"
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "%s = %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s = %s"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        aFL = ["deviceVendor", "categoryDeviceGroup", "deviceProduct"]
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type is list:
                aFL.extend(item.target)
            else:
                aFL.append(item.target)
        self.allowedFieldsList = list(set(aFL))

    # Skip logsource value from sigma document for separate path.
    def generateCleanValueNodeLogsource(self, value):
        return self.valueExpression % (self.cleanValue(str(value)))

    # Clearing values from special characters.
    def CleanNode(self, node):
        search_ptrn = re.compile(r"[\/\\@?#&_%*',\(\)\" ]")
        replace_ptrn = re.compile(r"[ \/\\@?#&_%*',\(\)\" ]")
        match = search_ptrn.search(str(node))
        new_node = list()
        if match:
            replaced_str = replace_ptrn.sub('*', node)
            node = [x for x in replaced_str.split('*') if x]
            new_node.extend(node)
        else:
            new_node.append(node)
        node = new_node
        return node

    # Clearing values from special characters.
    def generateMapItemNode(self, node):
        key, value = node
        if key in self.allowedFieldsList:
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                return self.mapExpression % (key, self.generateCleanValueNodeLogsource(value))
            elif type(value) is list:
                return self.generateMapItemListNode(key, value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        else:
            if self.mapListsSpecialHandling == False and type(value) in (
                    str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
                if type(value) is str:
                    new_value = list()
                    value = self.CleanNode(value)
                    if type(value) == list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                    else:
                        new_value.append(value)
                    if len(new_value)==1:
                        return "(" + self.generateANDNode(new_value) + ")"
                    else:
                        return "(" + self.generateORNode(new_value) + ")"
                else:
                    return self.generateValueNode(value)
            elif type(value) is list:
                new_value = list()
                for item in value:
                    item = self.CleanNode(item)
                    if type(item) is list and len(item) == 1:
                        new_value.append(self.valueExpression % item[0])
                    elif type(item) is list:
                        new_value.append(self.andToken.join([self.valueExpression % val for val in item]))
                    else:
                        new_value.append(item)
                return self.generateORNode(new_value)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))

    # for keywords values with space
    def generateValueNode(self, node):
        if type(node) is int:
            return self.cleanValue(str(node))
        if 'AND' in node:
            return "(" + self.cleanValue(str(node)) + ")"
        else:
            return self.cleanValue(str(node))

    # collect elements of Arcsight search using OR
    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s = %s' % (key, self.generateValueNode(item)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return " OR ".join(itemslist)

    # prepare of tail for every translate
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        const_title = ' AND type != 2 | rex field = flexString1 mode=sed "s//Sigma: {}/g"'
        for parsed in sigmaparser.condparsed:
            self.output.print(self.generateQuery(parsed) + const_title.format(sigmaparser.parsedyaml["title"]))

    # Add "( )" for values
    def generateSubexpressionNode(self, node):
        return self.subExpression % self.generateNode(node.items)

    # generateORNode algorithm for ArcSightBackend class.
    def generateORNode(self, node):
        if type(node) == sigma.parser.ConditionOR and all(isinstance(item, str) for item in node):
            new_value = list()
            for value in node:
                value = self.CleanNode(value)
                if type(value) is list:
                    new_value.append(self.andToken.join([self.valueExpression % val for val in value]))
                else:
                    new_value.append(value)
            return "(" + self.orToken.join([self.generateNode(val) for val in new_value]) + ")"
        return "(" + self.orToken.join([self.generateNode(val) for val in node]) + ")"
        
class QualysBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Qualys saved search. Contributed by SOC Prime. https://socprime.com"""
    identifier = "qualys"
    active = True
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "%s is null"
    notNullExpression = "not (%s is null)"
    mapExpression = "%s:`%s`"
    mapListsSpecialHandling = True
    PartialMatchFlag = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fl = []
        for item in self.sigmaconfig.fieldmappings.values():
            if item.target_type == list:
                fl.extend(item.target)
            else:
                fl.append(item.target)
        self.allowedFieldsList = list(set(fl))

    def generateORNode(self, node):
        new_list = []
        for val in node:
            if type(val) == tuple and not(val[0] in self.allowedFieldsList):
                pass
                # self.PartialMatchFlag = True
            else:
                new_list.append(val)

        generated = [self.generateNode(val) for val in new_list]
        filtered = [g for g in generated if g is not None]
        return self.orToken.join(filtered)

    def generateANDNode(self, node):
        new_list = []
        for val in node:
            if type(val) == tuple and not(val[0] in self.allowedFieldsList):
                self.PartialMatchFlag = True
            else:
                new_list.append(val)
        generated = [self.generateNode(val) for val in new_list]
        filtered = [g for g in generated if g is not None]
        return self.andToken.join(filtered)

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if key in self.allowedFieldsList:
                return self.mapExpression % (key, self.generateNode(value))
            else:
                return self.generateNode(value)
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = []
        for item in value:
            if key in self.allowedFieldsList:
                itemslist.append('%s:`%s`' % (key, self.generateValueNode(item)))
            else:
                itemslist.append('%s' % (self.generateValueNode(item)))
        return "(" + (" or ".join(itemslist)) + ")"

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        all_keys = set()

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            if query == "()":
                self.PartialMatchFlag = None

            if self.PartialMatchFlag == True:
                raise PartialMatchError(query)
            elif self.PartialMatchFlag == None:
                raise FullMatchError(query)
            else:
                self.output.print(query)
