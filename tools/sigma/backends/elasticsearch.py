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
from fnmatch import fnmatch
import sys
import os
from random import randrange
from distutils.util import strtobool

import sigma
import yaml
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier, SigmaTypeModifier
from sigma.parser.condition import ConditionOR, ConditionAND, NodeSubexpression

from sigma.config.mapping import ConditionalFieldMapping
from .base import BaseBackend, SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from .exceptions import NotSupportedError

class DeepFieldMappingMixin(object):
    def fieldNameMapping(self, fieldname, value):
        if isinstance(fieldname, str):
            get_config = self.sigmaconfig.fieldmappings.get(fieldname)
            if not get_config and '|' in fieldname:
                fieldname = fieldname.split('|', 1)[0]
                get_config = self.sigmaconfig.fieldmappings.get(fieldname)
            if isinstance(get_config, ConditionalFieldMapping):
                condition = self.sigmaconfig.fieldmappings.get(fieldname).conditions
                for key, item in self.logsource.items():
                    if condition.get(key) and condition.get(key, {}).get(item):
                        new_fieldname = condition.get(key, {}).get(item)
                        if any(new_fieldname):
                           return super().fieldNameMapping(new_fieldname[0], value)
        return super().fieldNameMapping(fieldname, value)

    def generate(self, sigmaparser):
        self.logsource = sigmaparser.parsedyaml.get("logsource", {})
        return super().generate(sigmaparser)

class ElasticsearchWildcardHandlingMixin(object):
    """
    Determine field mapping to keyword subfields depending on existence of wildcards in search values. Further,
    provide configurability with backend parameters.
    """
    options = SingleTextQueryBackend.options + (
            ("keyword_field", "keyword", "Keyword sub-field name (default is: '.keyword'). Set blank value if all keyword fields are the base(top-level) field. Additionally see 'keyword_base_fields' for more granular control of the base & subfield situation.", None),
            ("analyzed_sub_field_name", "", "Analyzed sub-field name. By default analyzed field is the base field. Therefore, use this option to make the analyzed field a subfield. An example value would be '.text' ", None),
            ("analyzed_sub_fields", None, "Fields that have an analyzed sub-field.", None),
            ("keyword_base_fields", None, "Fields that the keyword is base (top-level) field. By default analyzed field is the base field. So use this option to change that logic. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("keyword_whitelist", None, "Fields to always set as keyword. Bypasses case insensitive options. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("keyword_blacklist", None, "Fields to never set as keyword (ie: always set as analyzed field). Bypasses case insensitive options. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("case_insensitive_whitelist", None, "Fields to make the values case insensitive regex. Automatically sets the field as a keyword. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("case_insensitive_blacklist", None, "Fields to exclude from being made into case insensitive regex. Valid options are: list of fields, single field. Also, wildcards * and ? allowed.", None),
            ("wildcard_use_keyword", "true", "Use analyzed field or wildcard field if the query uses a wildcard value (ie: '*mall_wear.exe'). Set this to 'False' to use analyzed field or wildcard field. Valid options are: true/false", None),
            )
    reContainsWildcard = re.compile("(?:(?<!\\\\)|\\\\\\\\)[*?]").search
    uuid_regex = re.compile( "[0-9a-fA-F]{8}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{4}(\\\)?-[0-9a-fA-F]{12}", re.IGNORECASE )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.matchKeyword = True
        self.CaseInSensitiveField = False
        self.keyword_field = self.keyword_field.strip().strip('.') # Prevent mistake if user added a '.' or field has spaces
        self.analyzed_sub_field_name = self.analyzed_sub_field_name.strip().strip('.') # Prevent mistake if user added a '.' or field has spaces
        try:
            self.keyword_base_fields = self.keyword_base_fields.replace(' ','').split(',')
        except AttributeError:
            self.keyword_base_fields = list()
        try:
            self.analyzed_sub_fields = self.analyzed_sub_fields.replace(' ','').split(',')
        except AttributeError:
            self.analyzed_sub_fields = list()
        try:
            self.keyword_whitelist = self.keyword_whitelist.replace(' ','').split(',')
        except AttributeError:
            self.keyword_whitelist = list()
        try:
            self.keyword_blacklist = self.keyword_blacklist.replace(' ','').split(',')
        except AttributeError:
            self.keyword_blacklist = list()
        try:
            self.case_insensitive_whitelist = self.case_insensitive_whitelist.replace(' ','').split(',')
        except AttributeError:
            self.case_insensitive_whitelist = list()
        try:
            self.case_insensitive_blacklist = self.case_insensitive_blacklist.replace(' ','').split(',')
        except AttributeError:
            self.case_insensitive_blacklist = list()
        try:
            self.wildcard_use_keyword = strtobool(self.wildcard_use_keyword.lower().strip())
        except AttributeError:
            self.wildcard_use_keyword = False

    def containsWildcard(self, value):
        """Determine if value contains wildcard."""
        if type(value) == str:
            res = self.reContainsWildcard(value)
            return res
        else:
            return False

    def generateMapItemNode(self, node):
        fieldname, value = node
        if fieldname.lower().find("hash") != -1:
            if isinstance(value, list):
                res = []
                for item in value:
                    try:
                        res.extend([item.lower(), item.upper()])
                    except AttributeError:  # not a string (something that doesn't support upper/lower casing)
                        res.append(item)
                value = res
            elif isinstance(value, str):
                value = [value.upper(), value.lower()]
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
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

    def fieldNameMapping(self, fieldname, value, *agg_option):
        """
        Decide whether to use a keyword field or analyzed field. Using options on fields to make into keywords OR not and the field naming of keyword.
        Further, determine if values contain wildcards. Additionally, determine if case insensitive regex should be used. Finally,
        if field value should be quoted based on the field name decision and store it in object property.
        """
        force_keyword_whitelist = False # override everything AND set keyword and turn off case insensitivity
        force_keyword_blacklist = False # override everything AND set analyzed field and turn off case insensitivity
        force_keyword_type = False # make keyword
        keyword_subfield_name = self.keyword_field
        analyzed_subfield_name = self.analyzed_sub_field_name

        # Set naming for keyword fields
        if keyword_subfield_name == '':
            force_keyword_type = True
        elif len(self.keyword_base_fields) != 0 and any ([ fnmatch(fieldname, pattern) for pattern in self.keyword_base_fields ]):
            keyword_subfield_name = ''
        else:
            keyword_subfield_name = '.%s'%keyword_subfield_name

        # Set naming for analyzed fields
        if analyzed_subfield_name != '':
            analyzed_subfield_name = '.%s'%analyzed_subfield_name

        # force keyword on agg_option used in Elasticsearch DSL query key
        if agg_option:
            force_keyword_type = True

        # Only some analyzed subfield, so if not in this list then has to be keyword
        if len(self.analyzed_sub_fields) != 0 and not any ([ fnmatch(fieldname, pattern) for pattern in self.analyzed_sub_fields ]):
            force_keyword_type = True

        # Keyword (force) exclude
        if len(self.keyword_blacklist) != 0 and any ([ fnmatch(fieldname, pattern.strip()) for pattern in self.keyword_blacklist ]):
            force_keyword_blacklist = True
        # Keyword (force) include
        elif len(self.keyword_whitelist) != 0 and any ([ fnmatch(fieldname, pattern.strip()) for pattern in self.keyword_whitelist ]):
            force_keyword_whitelist = True

        # Set case insensitive regex
        if not (len( self.case_insensitive_blacklist ) != 0 and any([ fnmatch( fieldname, pattern ) for pattern in self.case_insensitive_blacklist ])) and len( self.case_insensitive_whitelist ) != 0 and any([ fnmatch( fieldname, pattern ) for pattern in self.case_insensitive_whitelist ]):
            self.CaseInSensitiveField = True
        else:
            self.CaseInSensitiveField = False

        # Set type and value
        if force_keyword_blacklist:
            self.matchKeyword = False
            self.CaseInSensitiveField = False
        elif force_keyword_whitelist:
            self.matchKeyword = True
            self.CaseInSensitiveField = False
        elif force_keyword_type:
            self.matchKeyword = True
        elif self.CaseInSensitiveField:
            self.matchKeyword = True
        elif self.wildcard_use_keyword and ( (type(value) == list and any(map(self.containsWildcard, value))) or self.containsWildcard(value) ):
            self.matchKeyword = True
        elif isinstance(value, SigmaRegularExpressionModifier):
            self.matchKeyword = True
        else:
            self.matchKeyword = False

        # Return compiled field name
        if self.matchKeyword:
            return '%s%s'%(fieldname, keyword_subfield_name)
        else:
            return '%s%s'%(fieldname, analyzed_subfield_name)

    def makeCaseInSensitiveValue(self, value):
        """
        Returns dictionary of if should be a regex (`is_regex`) and if regex the query value ('value')
        Converts the query(value) into a case insensitive regular expression (regex). ie: 'http' would get converted to '[hH][tT][pP][pP]'
        Adds the beginning and ending '/' to make regex query if still determined that it should be a regex
        """
        if value and not value == 'null' and not re.match(r'^/.*/$', value) and (re.search('[a-zA-Z]', value) and not re.match(self.uuid_regex, value) or self.containsWildcard(value)):  # re.search for alpha is fastest:
            # Turn single ending '\\' into non escaped (ie: '\\*')
            #value = re.sub( r"((?<!\\)(\\))\*$", "\g<1>\\*", value )
            # Make upper/lower
            value = re.sub( r"[A-Za-z]", lambda x: "[" + x.group( 0 ).upper() + x.group( 0 ).lower() + "]", value )
            # Turn `.` into wildcard, only if odd number of '\'(because this would mean already escaped)
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))\.", "\g<1>\.", value )
            # Turn `*` into wildcard, only if odd number of '\'(because this would mean already escaped)
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))\*", "\g<1>.*", value )
            # Escape additional values that are treated as specific "operators" within Elastic. (ie: @, ?, &, <, >, and ~)
            # reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/regexp-syntax.html#regexp-optional-operators
            value = re.sub( r"(((?<!\\)(\\\\)+)|(?<!\\))([@?&~<>])", "\g<1>\\\\\g<4>", value )
            # Validate regex
            try:
                re.compile(value)
                return {'is_regex': True, 'value': value}
            # Regex failed
            except re.error:
                raise TypeError( "Regular expression validation error for: '%s')" %str(value) )
        else:
            return { 'is_regex': False, 'value': value }

class ElasticsearchQuerystringBackend(DeepFieldMappingMixin, ElasticsearchWildcardHandlingMixin, SingleTextQueryBackend):
    """Converts Sigma rule into Elasticsearch query string. Only searches, no aggregations."""
    identifier = "es-qs"
    active = True

    reEscape = re.compile("([\s+\\-=!(){}\\[\\]^\"~:/]|(?<!\\\\)\\\\(?![*?\\\\])|\\\\u|&&|\\|\\|)")
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "%s"
    typedValueExpression = {
                SigmaRegularExpressionModifier: "/%s/"
            }
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
                if self.CaseInSensitiveField:
                    make_ci = self.makeCaseInSensitiveValue(result)
                    result = make_ci.get('value')
                    if make_ci.get('is_regex'): # Determine if still should be a regex
                        result = "/%s/" % result # Regex place holders for regex
                return result
            else:
                return "\"%s\"" % result

    def generateNOTNode(self, node):
        expression = super().generateNode(node.item)
        if expression:
            return "(%s%s)" % (self.notToken, expression)

    def generateSubexpressionNode(self, node):
        """Check for search not bound to a field and restrict search to keyword fields"""
        nodetype = type(node.items)
        if nodetype in { ConditionAND, ConditionOR } and type(node.items.items) == list and { type(item) for item in node.items.items }.issubset({str, int}):
            newitems = list()
            for item in node.items:
                newitem = item
                if type(item) == str:
                    if not item.startswith("*"):
                        newitem = "*" + newitem
                    if not item.endswith("*"):
                        newitem += "*"
                    newitems.append(newitem)
                else:
                    newitems.append(item)
            newnode = NodeSubexpression(nodetype(None, None, *newitems))
            self.matchKeyword = True
            result = "\\*.keyword:" + super().generateSubexpressionNode(newnode)
            self.matchKeyword = False       # one of the reasons why the converter needs some major overhaul
            return result
        else:
            return super().generateSubexpressionNode(node)

class ElasticsearchDSLBackend(DeepFieldMappingMixin, RulenameCommentMixin, ElasticsearchWildcardHandlingMixin, BaseBackend):
    """ElasticSearch DSL backend"""
    identifier = 'es-dsl'
    active = True
    options = RulenameCommentMixin.options + ElasticsearchWildcardHandlingMixin.options + (
        ("es", "http://localhost:9200", "Host and port of Elasticsearch instance", None),
        ("output", "import", "Output format: import = JSON search request, curl = Shell script that do the search queries via curl", "output_type"),
        ("set_size", "0", "value for the size of returned datasets.", None)
    )
    interval = None
    title = None
    reEscape = re.compile( "([\s+\\-=!(){}\\[\\]^\"~:/]|(?<!\\\\)\\\\(?![*?\\\\])|\\\\u|&&|\\|\\|)" )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queries = []

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        self.title = sigmaparser.parsedyaml.setdefault("title", "")
        logsource = sigmaparser.get_logsource()
        if logsource is None:
            self.indices = None
        else:
            self.indices = logsource.index
            if len(self.indices) == 0:
                self.indices = None

        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass

        for parsed in sigmaparser.condparsed:
            self.generateBefore(parsed)
            self.generateQuery(parsed)

            # size = X
            if int(self.set_size) > 0:
                self.queries[-1]['size'] = self.set_size

            # set _source from YAML-fields
            columns = list()
            mapped =None
            try:
                for field in sigmaparser.parsedyaml["fields"]:
                    mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
                    if type(mapped) == str:
                        columns.append(mapped)
                    elif type(mapped) == list:
                        columns.extend(mapped)
                    else:
                        raise TypeError("Field mapping must return string or list")

                fields = ",".join(str(x) for x in columns)
                self.queries[-1]['_source'] = columns
            except KeyError:    # no 'fields' attribute
                 mapped = None
                 pass

            self.generateAfter(parsed)

    def generateQuery(self, parsed):
        self.queries[-1]['query']['constant_score']['filter'] = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            self.generateAggregation(parsed.parsedAgg)

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

    def escapeSlashes(self, value):
        return value.replace("\\", "\\\\")

    def generateMapItemNode(self, node):
        key, value = node
        if type(value) is list:
            res = {'bool': {'should': []}}
            for v in value:
                key_mapped = self.fieldNameMapping(key, v)
                if self.matchKeyword:   # searches against keyword fields are wildcard searches, phrases otherwise
                    if self.CaseInSensitiveField:
                        queryType = 'regexp'
                        make_ci = self.makeCaseInSensitiveValue(self.reEscape.sub("\\\\\g<1>", str(v)))
                        value_cleaned = make_ci.get('value')
                        if not make_ci.get( 'is_regex' ):  # Determine if still should be a regex
                            queryType = 'wildcard'
                            value_cleaned = self.escapeSlashes( self.cleanValue( str( v ) ) )
                    else:
                        queryType = 'wildcard'
                        value_cleaned = self.escapeSlashes(self.cleanValue(str(v)))
                else:
                    queryType = 'match_phrase'
                    value_cleaned = self.cleanValue(str(v))
                res['bool']['should'].append({queryType: {key_mapped: value_cleaned}})
            return res
        elif value is None:
            key_mapped = self.fieldNameMapping(key, value)
            return { "bool": { "must_not": { "exists": { "field": key_mapped } } } }
        elif type(value) in (str, int):
            key_mapped = self.fieldNameMapping(key, value)
            if self.matchKeyword:  # searches against keyword fields are wildcard searches, phrases otherwise
                if self.CaseInSensitiveField:
                    queryType = 'regexp'
                    make_ci = self.makeCaseInSensitiveValue( self.reEscape.sub( "\\\\\g<1>", str( value ) ) )
                    value_cleaned = make_ci.get( 'value' )
                    if not make_ci.get( 'is_regex' ):  # Determine if still should be a regex
                        queryType = 'wildcard'
                        value_cleaned = self.escapeSlashes( self.cleanValue( str( value ) ) )
                else:
                    queryType = 'wildcard'
                    value_cleaned = self.escapeSlashes(self.cleanValue(str(value)))
            else:
                queryType = 'match_phrase'
                value_cleaned = self.cleanValue(str(value))
            return {queryType: {key_mapped: value_cleaned}}
        elif isinstance(value, SigmaRegularExpressionModifier):
            key_mapped = self.fieldNameMapping(key, value)
            return { 'regexp': { key_mapped: str(value) } }
        else:
            raise TypeError("Map values must be strings, numbers, lists, null or regular expression, not " + str(type(value)))

    def generateValueNode(self, node):
        return {'multi_match': {'query': node, 'fields': [], 'type': 'phrase'}}

    def generateNULLValueNode(self, node):
        return {'bool': {'must_not': {'exists': {'field': node.item}}}}

    def generateNotNULLValueNode(self, node):
        return {'exists': {'field': node.item}}

    def generateAggregation(self, agg):
        """
        Generates an Elasticsearch nested aggregation given a SigmaAggregationParser object

        Two conditions are handled here:
        a) "count() by MyGroupedField > X"
        b) "count(MyDistinctFieldName) by MyGroupedField > X'

        The case (b) is translated to a the following equivalent SQL query

        ```
        SELECT MyDistinctFieldName, COUNT(DISTINCT MyDistinctFieldName) FROM Table
        GROUP BY MyGroupedField HAVING COUNT(DISTINCT MyDistinctFieldName) > 1
        ```

        The resulting aggregation is set on 'self.queries[-1]["aggs"]' as a Python dict

        :param agg: Input SigmaAggregationParser object that defines a condition
        :return: None
        """
        if agg:
            if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT:
                if agg.groupfield is not None:
                    # If the aggregation is 'count(MyDistinctFieldName) by MyGroupedField > XYZ'
                    if agg.aggfield is not None:
                        count_agg_group_name = "{}_count".format(agg.groupfield)
                        count_distinct_agg_name = "{}_distinct".format(agg.aggfield)
                        script_limit = "params.count {} {}".format(agg.cond_op, agg.condition)
                        self.queries[-1]['aggs'] = {
                            count_agg_group_name: {
                                    "terms": {
                                        "field": "{}".format(agg.groupfield)
                                    },
                                    "aggs": {
                                        count_distinct_agg_name: {
                                            "cardinality": {
                                                "field": "{}".format(agg.aggfield)
                                            }
                                        },
                                        "limit": {
                                            "bucket_selector": {
                                                "buckets_path": {
                                                    "count": count_distinct_agg_name
                                                },
                                                "script": script_limit
                                            }
                                        }
                                    }
                                }
                            }
                    else:  # if the condition is count() by MyGroupedField > XYZ
                        group_aggname = "{}_count".format(agg.groupfield)
                        self.queries[-1]['aggs'] = {
                            group_aggname: {
                                'terms': {
                                    'field': '%s' % (agg.groupfield)
                                },
                                'aggs': {
                                    'limit': {
                                        'bucket_selector': {
                                            'buckets_path': {
                                                'count': group_aggname
                                            },
                                            'script': 'params.count %s %s' % (agg.cond_op, agg.condition)
                                        }
                                    }
                                }
                            }
                        }
            else:
                funcname = ""
                for name, idx in agg.aggfuncmap.items():
                    if idx == agg.aggfunc:
                        funcname = name
                        break
                raise NotImplementedError("%s : The '%s' aggregation operator is not yet implemented for this backend" % (self.title, funcname))

    def generateBefore(self, parsed):
        self.queries.append({'query': {'constant_score': {'filter': {}}}})

    def generateAfter(self, parsed):
        dateField = 'date'
        if self.sigmaconfig.config and 'dateField' in self.sigmaconfig.config:
            dateField = self.sigmaconfig.config['dateField']
        if self.interval:
            if 'bool' not in self.queries[-1]['query']['constant_score']['filter']:
                saved_simple_query = self.queries[-1]['query']['constant_score']['filter']
                self.queries[-1]['query']['constant_score']['filter'] = {'bool': {'must': []}}
                if len(saved_simple_query.keys()) > 0:
                    self.queries[-1]['query']['constant_score']['filter']['bool']['must'].append(saved_simple_query)
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
        description = sigmaparser.parsedyaml.setdefault("description", "")

        columns = list()
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
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
                rulename = self.getRuleName(sigmaparser)
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
                        "_id": rulename,
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
            if self.kibanaconf:
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
    supported_alert_methods = {'email', 'webhook','index'}
    options = ElasticsearchQuerystringBackend.options + (
            ("output", "curl", "Output format: curl = Shell script that imports queries in Watcher index with curl", "output_type"),
            ("es", "localhost:9200", "Host and port of Elasticsearch instance", None),
            ("watcher_url", "watcher", "Watcher URL: watcher (default)=_watcher/..., xpack=_xpack/wacher/... (deprecated)", None),
            ("filter_range","30m","Watcher time filter",None),
            ("action_throttle_period","15m","Throttle time of the action",None),

            ("alert_methods", "email", "Alert method(s) to use when the rule triggers, comma separated. Supported: " + ', '.join(supported_alert_methods), None),
            # Options for Email Action
            ("mail", "root@localhost", "Mail address for Watcher notification (only logging if not set)", None),
            ("mail_from", "root@localhost", "Mail address for Watcher notification (only logging if not set)", None),
            ("mail_profile", "standard", "Watcher provides three email profiles that control how MIME messages are structured: standard (default), gmail, and outlook.", None),

            # Options for WebHook Action
        ("http_host", "localhost", "Webhook host used for alert notification", None),
        ("http_port", "80", "Webhook port used for alert notification", None),
        ("http_scheme", "http", "Webhook scheme used for alert notification", None),
        ("http_user", None, "Webhook User used for alert notification", None),
        ("http_pass", None, "Webhook Password used for alert notification", None),
        ("http_uri_path", "/", "Webhook Uri used for alert notification", None),
        ("http_method", "POST", "Webhook Method used for alert notification", None),

        ("http_phost", None, "Webhook proxy host", None),
        ("http_pport", None, "Webhook Proxy port", None),
            # Options for Index Action
            ("index", "<log2alert-{now/d}>","Index name used to add the alerts", None), #by default it creates a new index every day
            ("type", "_doc","Index Type used to add the alerts", None)

            )
    watcher_urls = {
            "watcher": "_watcher",
            "xpack": "_xpack/watcher",
            }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watcher_alert = dict()
        self.url_prefix = self.watcher_urls[self.watcher_url]

    def generate(self, sigmaparser):
        # get the details if this alert occurs
        title = sigmaparser.parsedyaml.setdefault("title", "")
        description = sigmaparser.parsedyaml.setdefault("description", "")
        false_positives = sigmaparser.parsedyaml.setdefault("falsepositives", "")
        level = sigmaparser.parsedyaml.setdefault("level", "")
        tags = sigmaparser.parsedyaml.setdefault("tags", "")
        # Get time frame if exists
        interval = sigmaparser.parsedyaml["detection"].setdefault("timeframe", "30m")
        dateField = self.sigmaconfig.config.get("dateField", "timestamp")

        # creating condition
        indices = sigmaparser.get_logsource().index
        # How many results to be returned. Usually 0 but for index action we need it.
        size = 0

        for condition in sigmaparser.condparsed:
            rulename = self.getRuleName(sigmaparser)
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
                                        "field": condition.parsedAgg.aggfield,
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
                                        "field": condition.parsedAgg.groupfield,
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
            try:
                eaction={} #email action
                waction={} #webhook action
                iaction={} #index action
                action={}
                alert_methods = self.alert_methods.split(',')
                if 'email' in alert_methods:
                    # mail notification if mail address is given
                    email = self.mail
                    mail_profile = self.mail_profile
                    mail_from = self.mail_from
                    action_throttle_period = self.action_throttle_period
                    eaction = {
                        "send_email": {
                                "throttle_period": action_throttle_period,
                                "email": {
                                    "profile": mail_profile,
                                    "from": mail_from,
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
                if 'webhook' in alert_methods: # WebHook Action. Sending metadata to a webservice. Added timestamp to metadata
                    http_scheme = self.http_scheme
                    http_host = self.http_host
                    http_port = self.http_port
                    http_uri_path = self.http_uri_path
                    http_method = self.http_method
                    http_phost = self.http_phost
                    http_pport = self.http_pport
                    http_user = self.http_user
                    http_pass = self.http_pass
                    waction = {
            "httppost":{
                            "transform":{
                                "script": "ctx.metadata.timestamp=ctx.trigger.scheduled_time;"
                                },
                            "webhook":{
                            "scheme"  : http_scheme,
                            "host"    : http_host,
                            "port"    : int(http_port),
                            "method"  : http_method,
                                "path"    : http_uri_path,
                            "params"  : {},
                            "headers" : {"Content-Type"                      : "application/json"},
                            "body"    : "{{#toJson}}ctx.metadata{{/toJson}}"
                            }
            }
            }
                    if (http_user) and (http_pass):
                        auth={
                            "basic":{
                                "username":http_user,
                                "password":http_pass
                            }
                        }
                        waction['httppost']['webhook']['auth']={}
                        waction['httppost']['webhook']['auth']=auth

                    if (http_phost) and (http_pport): #As defined in documentation
                        waction['httppost']['webhook']['proxy']={}
                        waction['httppost']['webhook']['proxy']['host']=http_phost
                        waction['httppost']['webhook']['proxy']['port']=http_pport

                if 'index' in alert_methods: #Index Action. Adding metadata to actual events and send them in another index
                    index = self.index
                    dtype = self.type
                    size=1000 #I presume it will not be more than 1000 events detected
                    iaction = {
                            "elastic":{
                                "transform":{ #adding title, description, tags on the event
                                    "script": "ctx.payload.transform = [];for (int j=0;j<ctx.payload.hits.total;j++){ctx.payload.hits.hits[j]._source.alerttimestamp=ctx.trigger.scheduled_time;ctx.payload.hits.hits[j]._source.alerttitle=ctx.metadata.title;ctx.payload.hits.hits[j]._source.alertquery=ctx.metadata.query;ctx.payload.hits.hits[j]._source.alertdescription=ctx.metadata.description;ctx.payload.hits.hits[j]._source.tags=ctx.metadata.tags;ctx.payload.transform.add(ctx.payload.hits.hits[j]._source)} return ['_doc': ctx.payload.transform];"
                                },
                                "index":{
                                    "index": index,
                                    "doc_type":dtype
                                }
                            }
                    }

                action = {**eaction,**waction, **iaction}

            except KeyError as k:    # no mail address given, generate log action
                action = {
                        "logging-action": {
                            "logging": {
                                "text": action_subject + ": " + action_body
                                }
                            }
                        }

            self.watcher_alert[rulename] = {
                              "metadata": {
                                  "title": title,
                                  "description": description,
                                  "tags": tags,
                                  "query":result #addede query to metadata. very useful in kibana to do drill down directly from discover
                              },
                              "trigger": {
                                "schedule": {
                                  "interval": interval  # how often the watcher should check
                                }
                              },
                              "input": {
                                "search": {
                                  "request": {
                                    "body": {
                                      "size": size,
                                      "query": {
                                        "bool": {
                                            "must":[{
                                                "query_string": {
                                                    "query": result,  # this is where the elasticsearch query syntax goes
                                                    "analyze_wildcard": True
                                                }
                                                }],
                                            "filter":
                                                {
                                                    "range":{
                                                        dateField:{
                                                            "gte":"now-%s/m"%self.filter_range #filter only for the last x minutes events
                                                            }
                                                        }
                                                }
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
                result += "PUT %s/watch/%s\n%s\n" % (self.url_prefix, rulename, json.dumps(rule, indent=2))
            elif self.output_type == "curl":      # output curl command line
                result += "curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- %s/%s/watch/%s <<EOF\n%s\nEOF\n" % (self.es, self.url_prefix, rulename, json.dumps(rule, indent=2))
            elif self.output_type == "json":    # output compressed watcher json, one per line
                result += json.dumps(rule) + "\n"
            else:
                raise NotImplementedError("Output type '%s' not supported" % self.output_type)
        return result

class ElastalertBackend(DeepFieldMappingMixin, MultiRuleOutputMixin):
    """Elastalert backend"""
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
        self.logsource = sigmaparser.parsedyaml.get("logsource", {})
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
            self.queries = []

            #Handle aggregation
            if parsed.parsedAgg:
                if parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MIN or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MAX or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_AVG or parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_SUM:
                    if parsed.parsedAgg.groupfield is not None:
                        rule_object['query_key'] = self.fieldNameMapping(parsed.parsedAgg.groupfield, '*')
                    rule_object['type'] = "metric_aggregation"
                    rule_object['buffer_time'] = interval
                    rule_object['doc_type'] = "doc"

                    if parsed.parsedAgg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT:
                        rule_object['metric_agg_type'] = "cardinality"
                    else:
                        rule_object['metric_agg_type'] = parsed.parsedAgg.aggfunc_notrans

                    if parsed.parsedAgg.aggfield:
                        rule_object['metric_agg_key'] = self.fieldNameMapping(parsed.parsedAgg.aggfield, '*')
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
                    print('Warning: the Elastalert HTTP POST method is selected but no URL has been provided.', file=sys.stderr)
                else:
                    rule_object['http_post_url'] = self.http_post_url

                rule_object['alert'].append('post')
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
            if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT or \
                    agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MIN or \
                    agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_MAX or \
                    agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_AVG or \
                    agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_SUM:
                return ""
            else:
                for name, idx in agg.aggfuncmap.items():
                    if idx == agg.aggfunc:
                        funcname = name
                        break
                raise NotImplementedError("%s : The '%s' aggregation operator is not yet implemented for this backend" % ( self.title, funcname))

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
            result += yaml.dump(rule, default_flow_style=False, width=10000)
            result += '\n'
        return result

class ElastalertBackendDsl(ElastalertBackend, ElasticsearchDSLBackend):
    """Elastalert backend"""
    identifier = 'elastalert-dsl'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generateQuery(self, parsed):
        #Generate ES DSL Query
        super().generateBefore(parsed)
        super().generateQuery(parsed)
        super().generateAfter(parsed)
        return self.queries

class ElastalertBackendQs(ElastalertBackend, ElasticsearchQuerystringBackend):
    """Elastalert backend"""
    identifier = 'elastalert'
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generateQuery(self, parsed):
        #Generate ES QS Query
        return [{ 'query' : { 'query_string' : { 'query' : super().generateQuery(parsed) } } }]

class ElasticSearchRuleBackend(ElasticsearchQuerystringBackend):
    """Elasticsearch detection rule backend"""
    identifier = "es-rule"
    active = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tactics = self._load_mitre_file("tactics")
        self.techniques = self._load_mitre_file("techniques")

    def _load_mitre_file(self, mitre_type):
        try:
            backend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config", "mitre"))
            path = os.path.join(backend_dir,"{}.json".format(mitre_type))
            with open(path, 'r') as config_file:
                config = json.load(config_file)
                return config
        except (IOError, OSError) as e:
            print("Failed to open {} configuration file '%s': %s".format(path, str(e)), file=sys.stderr)
            return []
        except json.JSONDecodeError as e:
            print("Failed to parse {} configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            return []

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            index = sigmaparser.get_logsource().index
            if len(index) == 0:
                index = ["apm-*-transaction", "auditbeat-*", "endgame-*", "filebeat-*", "packetbeat-*", "winlogbeat-*"]
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs, index)
            return rule

    def create_threat_description(self, tactics_list, techniques_list):
        threat_list = list()
        for tactic in tactics_list:
            temp_tactics = {
                "tactic": {
                    "id": tactic.get("external_id", ""),
                    "reference": tactic.get("url", ""),
                    "name": tactic.get("tactic", "")
                },
                "framework": "MITRE ATT&CK®"
            }
            temp_techniques = list()
            for tech in techniques_list:
                if tactic.get("tactic", "") in tech.get("tactic", []):
                    temp_techniques.append({
                                "id": tech.get("technique_id", ""),
                                "name": tech.get("technique", ""),
                                "reference": tech.get("url", "")
                            })
            temp_tactics.update({"technique": temp_techniques})
            threat_list.append(temp_tactics)
        return threat_list

    def find_tactics(self, key_name=None, key_id=None):
        for tactic in self.tactics:
            if key_name and key_name == tactic.get("tactic", ""):
                return tactic
            if key_id and key_id == tactic.get("external_id", ""):
                return tactic

    def find_technique(self, key_id=None):
        for technique in self.techniques:
            if key_id and key_id == technique.get("technique_id", ""):
                return technique

    def map_risk_score(self, level):
        if level == "low":
            return randrange(0,22)
        elif level == "medium":
            return randrange(22,48)
        elif level == "high":
            return randrange(48,74)
        elif level == "critical":
            return randrange(74,101)

    def create_rule(self, configs, index):
        tags = configs.get("tags", [])
        tactics_list = list()
        technics_list = list()
        new_tags = list()

        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[t][0-9]{4}", tag, re.IGNORECASE):
                tech = self.find_technique(tag.title())
                if tech:
                    new_tags.append(tag.title())
                    technics_list.append(tech)
            else:
                if "_" in tag:
                    tag_list = tag.split("_")
                    tag_list = [item.title() for item in tag_list]
                    tact = self.find_tactics(key_name=" ".join(tag_list))
                    if tact:
                        new_tags.append(" ".join(tag_list))
                        tactics_list.append(tact)
                elif re.match("[ta][0-9]{4}", tag, re.IGNORECASE):
                    tact = self.find_tactics(key_id=tag.upper())
                    if tact:
                        new_tags.append(tag.upper())
                        tactics_list.append(tact)
                else:
                    tact = self.find_tactics(key_name=tag.title())
                    if tact:
                        new_tags.append(tag.title())
                        tactics_list.append(tact)
        threat = self.create_threat_description(tactics_list=tactics_list, techniques_list=technics_list)
        rule_name = configs.get("title", "").lower()
        rule_id = re.sub(re.compile('[()*+!,\[\].\s"]'), "_", rule_name)
        risk_score = self.map_risk_score(configs.get("level", "medium"))
        references = configs.get("reference")
        if references is None:
            references = configs.get("references")
        rule = {
            "description": configs.get("description", ""),
            "enabled": True,
            "false_positives": configs.get('falsepositives', "Unkown"),
            "filters": [],
            "from": "now-360s",
            "immutable": False,
            "index": index,
            "interval": "5m",
            "rule_id": rule_id,
            "language": "lucene",
            "output_index": ".siem-signals-default",
            "max_signals": 100,
            "risk_score": risk_score,
            "name": configs.get("title", ""),
            "query":configs.get("translation"),
            "meta": {
                "from": "1m"
            },
            "severity": configs.get("level", "medium"),
            "tags": new_tags,
            "to": "now",
            "type": "query",
            "threat": threat,
            "version": 1
        }
        if references:
            rule.update({"references": references})
        return json.dumps(rule)

class KibanaNdjsonBackend(ElasticsearchQuerystringBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into Kibana JSON Configuration files (searches only)."""
    identifier = "kibana-ndjson"
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
        description = sigmaparser.parsedyaml.setdefault("description", "")

        columns = list()
        try:
            for field in sigmaparser.parsedyaml["fields"]:
                mapped = sigmaparser.config.get_fieldmapping(field).resolve_fieldname(field, sigmaparser)
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
                rulename = self.getRuleName(sigmaparser)
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
                        "id": rulename,
                        "type": "search",
                        "attributes": {
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
                        },
                        "references": [
                            {
                                "id": index,
                                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                                "type": "index-pattern"
                            }
                        ]
                    })

    def finalize(self):
        if self.output_type == "import":        # output format that can be imported via Kibana UI
            for item in self.kibanaconf:    # JSONize kibanaSavedObjectMeta.searchSourceJSON
                item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.dumps(item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
            if self.kibanaconf:
                ndjson = ""
                for item in self.kibanaconf:
                    ndjson += json.dumps(item)
                    ndjson += "\n"
                return ndjson
        elif self.output_type == "curl":
            for item in self.indexsearch:
                return item
            for item in self.kibanaconf:
                item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON']['index'] = "$" + self.index_variable_name(item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON']['index'])   # replace index pattern with reference to variable that will contain Kibana index UUID at script runtime
                item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.dumps(item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])     # Convert it to JSON string as expected by Kibana
                item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = item['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'].replace("\\", "\\\\")      # Add further escaping for escaped quotes for shell
                return "curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- '{es}/{index}/doc/{doc_id}' <<EOF\n{doc}\nEOF".format(
                        es=self.es,
                        index=self.index,
                        doc_id="search:" + item['_id'],
                        doc=json.dumps({
                            "type": "search",
                            "search": item['attributes']
                            }, indent=2)
                        )
        else:
            raise NotImplementedError("Output type '%s' not supported" % self.output_type)

    def index_variable_name(self, index):
        return "index_" + index.replace("-", "__").replace("*", "X")
