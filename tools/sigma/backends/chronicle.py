import re
from datetime import datetime

import sigma
from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.mixins import MultiRuleOutputMixin

from .exceptions import NotSupportedError
from ..parser.condition import SigmaAggregationParser
from ..parser.modifiers.base import SigmaTypeModifier
from ..parser.modifiers.transform import SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier
from ..parser.modifiers.type import SigmaRegularExpressionModifier

comparative = ["greater_than",
               "greater_equal",
               "less_than",
               "less_equal",
               ]

class ChronicleBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Google Chronicle YARA-L. Contributed by SOC Prime. https://socprime.com"""
    identifier = "chronicle"
    active = True
    andToken = " and "
    #\\\
    reEscape = re.compile('([\"]|(\\\\))')
    reClear = re.compile('`')

    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    valueExpression = "\"%s\""
    mapExpression = "%s = %s"
    listExpression = "(%s)"
    listSeparator = " or "
    config_required = True
    mapListsSpecialHandling = True

    def __init__(self, *args, **kwargs):
        self.defaultEventName = "event"
        self.condition_name = None
        self.parsed_detection = None
        self.author = None
        self.description = None
        self.created = None
        self.title = None
        self.references = None
        self.rule_count = 0
        return super().__init__(*args, **kwargs)

    def cleanValue(self, val):
        if val and isinstance(val, str) and val.endswith("/"):
            val = val.rstrip("/")
        if val and isinstance(val, str) and val.startswith("\\"):
            val = val.lstrip("\\")
        return super().cleanValue(val)

    def parseTitle(self, title):
        new_title = re.sub(re.compile('[()*:;+!,\[\].?"-/]'), "", title.lower())
        new_title = re.sub(re.compile('\s'), "_", new_title.lower())
        index = 0
        for i, title_char in enumerate(new_title):
            if not title_char.isdigit():
                index = i
                break
        new_title = new_title[index:]
        new_title = new_title.strip("_")
        return new_title

    def generateMapItemNode(self, node):
        fieldname, value = node

        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if type(value) in (str, int):
            return self.regex_check(transformed_fieldname=transformed_fieldname, val=value)
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def createFinalRule(self, body):
        # Spaces required in rule for structure
        function_name = self.parseTitle(self.title)
        if self.rule_count != 0:
            function_name += "_part_{}".format(self.rule_count)

        meta = """ meta:\n    author = \"{author}\"\n    description = \"{description}\"\n    reference = \"{reference}\"\n    version = \"0.01\"""".format(
            author=self.author, description=self.description, reference=""
        )
        if self.created:
            meta += "\n    created = \"{}\"".format(self.created)
        if any(self.logsource):
            logsources = "\n    ".join([f'{i} = "{j}"' for i, j in self.logsource.items() if i not in ("description", "definition")])
            meta += "\n    {}".format(logsources)
        if self.tags:
            tags = ", ".join([item.replace("attack.", "") for item in self.tags])
            meta += "\n    mitre = \"{}\"".format(tags)
        condition_func = """  condition:\n    {condition}""".format(condition=self.condition)
        result = """rule {function_name} {{\n{meta}\n\n  events:\n{function}\n\n{condition}\n}}""".format(
            function_name=function_name,
            meta=meta,
            function=body,
            condition=condition_func
        )
        self.rule_count += 1
        return result

    def fieldNameMapping(self, fieldname, value):
        return f"${self.condition_name}.{fieldname}"

    def regex_check(self, transformed_fieldname, val):
        if val and isinstance(val, str) and '*' in val:
            val = val.replace("\*", "*")
            val = self.cleanValue(val)
            val = val.replace("(", "\(")
            val = val.replace(")", "\)")
            val = re.compile(r'([+.?])').sub("\\\\\g<1>", val)
            val = val.replace("*", ".*")
            return f"re.regex({transformed_fieldname}, `{val}`)"
        if val and isinstance(val, str):
            return self.mapExpression % (transformed_fieldname, self.generateNode(val))
        else:
            return self.mapExpression % (transformed_fieldname, self.generateNode(val))

    def generateMapItemListNode(self, fieldname, value):
        list_query = []
        for item in value:
            updated_field_value = self.regex_check(transformed_fieldname=fieldname, val=item)
            list_query.append(updated_field_value)
        if len(list_query) > 1:
            return "(" + " or ".join(list_query) + ")"
        return list_query[0]

    def generate(self, sigmaparser):
        detection = sigmaparser.parsedyaml.get("detection")
        condition_name = [item for item in detection.keys() if item not in ("condition", "keywords")]
        if any(condition_name):
            self.condition_name = condition_name[0]
        else:
            self.condition_name = "event"
        self.author = sigmaparser.parsedyaml.get("author")
        self.title = sigmaparser.parsedyaml.get("title")
        description = "{} Author: {}.".format(sigmaparser.parsedyaml.get("description"), self.author)
        description = description.replace("\\", "\\\\")
        description = description.replace("\n", "")
        self.description = description.replace('"', '\\"')
        self.created = sigmaparser.parsedyaml.get("date", datetime.now().strftime("%Y-%m-%d"))
        references = sigmaparser.parsedyaml.get("reference", [])
        if not any(references):
            references = sigmaparser.parsedyaml.get("references", [])
        self.references = references
        self.logsource = sigmaparser.parsedyaml.get("logsource") if sigmaparser.parsedyaml.get("logsource") else sigmaparser.parsedyaml.get("logsources", {})
        self.tags = sigmaparser.parsedyaml.get("tags")
        for parsed in sigmaparser.condparsed:
            aggregation = None
            translate = self.generateQuery(parsed)
            self.condition = "${}".format(self.condition_name)
            if parsed.parsedAgg:
                translate = self.generateAggregation(agg=parsed.parsedAgg, body=translate)
            return self.createFinalRule(body=translate)

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        return result

    def generateAggregation(self, agg, body):
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError(
                "The 'near' aggregation operator is not "
                + f"implemented for the %s backend" % self.identifier
            )
        if agg.aggfunc_notrans != 'count' and agg.aggfield is None:
            raise NotSupportedError(
                "The '%s' aggregation operator " % agg.aggfunc_notrans
                + "must have an aggregation field for the %s backend" % self.identifier
            )
        if agg.aggfunc_notrans == 'count':
            if agg.groupfield:
                self.condition = "${condition} and #target {op} {cond}".format(condition=self.condition_name,
                                                                                          field=agg.groupfield,
                                                                                          op=agg.cond_op,
                                                                                          cond=agg.condition)
                body += "\n${condition}.{field} = $target".format(condition=self.condition_name, field=agg.groupfield,)
            else:
                self.condition = "#{} {} {}".format(self.condition_name, agg.cond_op, agg.condition)
            return body