import re
import sigma
from .base import SingleTextQueryBackend
from sigma.parser.condition import SigmaAggregationParser, NodeSubexpression, ConditionAND, ConditionOR, ConditionNOT
from sigma.parser.exceptions import SigmaParseError
from .mixins import MultiRuleOutputMixin
from sigma.parser.modifiers.transform import SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from ..parser.modifiers.base import SigmaTypeModifier


def convert_sigma_level_to_uberagent_risk_score(level):
    """Converts the given Sigma rule level to uberAgent ESA RiskScore property."""
    levels = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25
    }

    if level in levels:
        return levels[level]

    return 0


def convert_sigma_name_to_uberagent_tag(name):
    """Converts the given Sigma rule name to uberAgent ESA Tag property."""
    tag = name.lower().replace(" ", "-")
    tag = re.sub(r"-{2,}", "-", tag, 0, re.IGNORECASE)
    return tag


def convert_sigma_category_to_uberagent_event_type(category):
    categories = {
        "process_creation": "Process.Start",
        "image_load": "Image.Load",
        "dns": "Dns.Query"
    }

    if category in categories:
        return categories[category]

    return None


def is_sigma_category_supported(category):
    """Returns whether uberAgent ESA knows the given category or not."""
    return convert_sigma_category_to_uberagent_event_type(category) is not None


class IgnoreTypedModifierException(Exception):
    """
    IgnoreTypedModifierException
    Helper class to ignore exceptions of type identifiers that are not yet supported.
    """
    pass


class IgnoreFieldException(Exception):
    """
    IgnoreFieldException
    Helper class to ignore exceptions of specific fields that are not yet supported.
    """
    pass


class IgnoreAggregationException(Exception):
    """
    IgnoreAggregationException
    Helper class to ignore exceptions of aggregation rules that are not yet supported.
    """


class MalformedRuleException(Exception):
    """
    MalformedRuleException
    Helper class to ignore exceptions of malformed rules.
    """
    pass


class ActivityMonitoringRule:
    """
    ActivityMonitoringRule
    This class wraps a [ActivityMonitoringRule] configuration block.
    """

    def __init__(self):
        self.name = ""
        self.event_type = None
        self.tag = ""
        self.query = ""
        self.risk_score = 0
        self.description = ""
        self.sigma_level = ""

        # Specifies the properties that are being evaluated and send to the backend
        # if an Activity Monitoring rule is matched.
        self.generic_properties = {
            "Process.": [
                "Process.Hash.MD5",
                "Process.Hash.SHA1",
                "Process.Hash.SHA256",
                "Process.Hash.IMP"
            ],
            "Image.": [
                "Image.Name",
                "Image.Path",
                "Image.Hash.MD5",
                "Image.Hash.SHA1",
                "Image.Hash.SHA256",
                "Image.Hash.IMP"
            ],
            "Net.": [
                "Net.Target.Ip",
                "Net.Target.Name",
                "Net.Target.Port",
                "Net.Target.Protocol"
            ],
            "Reg.": [
                "Reg.Key.Path",
                "Reg.Key.Path.New",
                "Reg.Key.Path.Old"
                "Reg.Key.Name",
                "Reg.Parent.Key.Path",
                "Reg.Value.Name",
                "Reg.File.Name",
                "Reg.Key.Sddl",
                "Reg.Key.Hive",
            ],
            "Dns.": [
                "Dns.QueryRequest",
                "Dns.QueryResponse"
            ]
        }

    def set_query(self, query):
        """Sets the generated query."""
        self.query = query

    def set_name(self, name):
        """Sets the RuleName."""
        self.name = name

    def set_tag(self, tag):
        """Sets the Tag property."""
        self.tag = tag

    def set_event_type(self, event_type):
        """Sets the EventType property."""
        self.event_type = event_type

    def set_risk_score(self, risk_score):
        """Sets the RiskScore property."""
        self.risk_score = risk_score

    def set_sigma_level(self, level):
        """Sets the Sigma rule level."""
        self.sigma_level = level

    def set_description(self, description):
        """Set the Description property."""
        self.description = description

    def _prefixed_tag(self):
        prefixes = {
            "Process.Start": "proc-start"
        }

        if self.event_type not in prefixes:
            return self.tag

        return "{}-{}".format(prefixes[self.event_type], self.tag)

    def __str__(self):
        """Builds and returns the [ActivityMonitoringRule] configuration block."""
        result = "[ActivityMonitoringRule]\n"

        # The Description is optional.
        if len(self.description) > 0:
            result += "# {}\n".format(self.description)

        # Make sure all required properties have at least a value that is somehow usable.
        if self.event_type is None:
            raise MalformedRuleException()

        if len(self.tag) == 0:
            raise MalformedRuleException()

        if len(self.name) == 0:
            raise MalformedRuleException()

        if len(self.query) == 0:
            raise MalformedRuleException()

        result += "RuleName = {}\n".format(self.name)
        result += "EventType = {}\n".format(self.event_type)
        result += "Tag = {}\n".format(self._prefixed_tag())

        # The RiskScore is optional.
        # Set it, if a risk_score value is present.
        if self.risk_score > 0:
            result += "RiskScore = {}\n".format(self.risk_score)

        result += "Query = {}\n".format(self.query)

        counter = 1
        for event_type_prefix in self.generic_properties:
            if self.event_type.startswith(event_type_prefix):
                for prop in self.generic_properties[event_type_prefix]:
                    # Generic properties are limited to 10.
                    if counter > 10:
                        break

                    result += "GenericProperty{} = {}\n".format(counter, prop)
                    counter += 1

        return result


def get_parser_properties(sigmaparser):
    title = sigmaparser.parsedyaml['title']
    level = sigmaparser.parsedyaml['level']
    description = sigmaparser.parsedyaml['description']
    condition = sigmaparser.parsedyaml['detection']['condition']
    logsource = sigmaparser.parsedyaml['logsource']
    category = ''
    if 'category' in logsource:
        category = logsource['category'].lower()

    product = ''
    if 'product' in logsource:
        product = logsource['product'].lower()

    service = ''
    if 'service' in logsource:
        service = logsource['service'].lower()

    return product, category, service, title, level, condition, description


def write_file_header(f, level):
    f.write("#\n")
    f.write("# The rules are generated from the Sigma GitHub repository at https://github.com/Neo23x0/sigma\n")
    f.write("# Follow these steps to get the latest rules from the repository with Python\n")
    f.write("#    1. Clone the repository locally\n")
    f.write("#    2. Using a commandline, change working directory to the just cloned repository\n")
    f.write("#    3. Run sigmac -I --target uberagent -r rules/\n")
    f.write("#\n")
    f.write("# The rules in this file are marked with sigma-level: {}\n".format(level))
    f.write("#\n\n")


class uberAgentBackend(SingleTextQueryBackend):
    """Converts Sigma rule into uberAgent ESA's process tagging rules."""
    identifier = "uberagent"
    active = True
    config_required = False
    rule = None
    current_category = None

    #
    # SingleTextQueryBackend
    #
    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "[%s]"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "%s == ''"
    notNullExpression = "%s != ''"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"

    # Syntax for swapping wildcard conditions: Adding \ as escape character
    # Wildcard conditions are based on modifiers such as contains,
    # startswith, endswith
    mapWildcard = "%s like r%s"

    #
    # uberAgent field mapping
    #
    fieldMapping = {
        "commandline": "Process.CommandLine",
        "image": "Process.Path",
        "originalfilename": "Process.Name",
        "imageloaded": "Image.Path",
        "imagepath": "Image.Path",
        "parentcommandline": "Parent.CommandLine",
        "parentprocessname": "Parent.Name",
        "parentimage": "Parent.Path",
        "path": "Process.Path",
        "processcommandline": "Process.CommandLine",
        "command": "Process.CommandLine",
        "processname": "Process.Name",
        "user": "Process.User",
        "username": "Process.User",
        "company": "Process.Company"
    }

    fieldMappingPerCategory = {
        "process_creation": {
            "sha1": "Process.Hash.SHA1",
            "imphash": "Process.Hash.IMP",
            "childimage": "Process.Path"
            # Not yet supported.
            # "signed": "Process.IsSigned"
        },
        "image_load": {
            "sha1": "Image.Hash.SHA1",
            "imphash": "Image.Hash.IMP",
            "childimage": "Image.Path"
            # Not yet supported.
            # "signed": "Image.IsSigned"
        },
        "dns": {
            "query": "Dns.QueryRequest",
            # Not yet supported.
            # "record_type": "Dns.QueryResponseType",
            "answer": "Dns.QueryResponse"
        }
    }

    # We ignore some fields that we don't support yet but we don't want them to
    # throw errors in the console since we are aware of this.
    ignoreFieldList = [
        "description",
        "product",
        "logonid",
        "integritylevel",
        "currentdirectory",
        "parentintegritylevel",
        "eventid",
        "parentuser",
        "parent_domain",
        "signed",
        "parentofparentimage",
        "record_type"
    ]

    rules = []

    def fieldNameMapping(self, fieldname, value):
        key = fieldname.lower()

        if self.current_category is not None:
            if self.current_category in self.fieldMappingPerCategory:
                if key in self.fieldMappingPerCategory[self.current_category]:
                    return self.fieldMappingPerCategory[self.current_category][key]

        if key not in self.fieldMapping:
            if key in self.ignoreFieldList:
                raise IgnoreFieldException()
            else:
                raise NotImplementedError('The fieldname %s is not implemented.' % fieldname)

        return self.fieldMapping[key]

    def generateQuery(self, parsed):
        if parsed.parsedAgg:
            raise IgnoreAggregationException()

        return self.generateNode(parsed.parsedSearch)

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        product, category, service, title, level, condition, description = get_parser_properties(sigmaparser)

        # Do not generate a rule if the given category is unsupported by now.
        if not is_sigma_category_supported(category):
            return ""

        # We support windows rules and generic rules that don't have a specific product specifier - such as DNS.
        if product not in ["windows", ""]:
            return ""

        self.current_category = category

        try:
            rule = ActivityMonitoringRule()

            query = super().generate(sigmaparser)
            if len(query) > 0:
                rule.set_name(title)
                rule.set_tag(convert_sigma_name_to_uberagent_tag(title))
                rule.set_event_type(convert_sigma_category_to_uberagent_event_type(category))
                rule.set_query(query)
                rule.set_risk_score(convert_sigma_level_to_uberagent_risk_score(level))
                rule.set_sigma_level(level)
                rule.set_description(description)
                self.rules.append(rule)
                print("Generated rule <{}>.. [level: {}]".format(rule.name, level))
        except IgnoreTypedModifierException:
            return ""
        except IgnoreAggregationException:
            return ""
        except IgnoreFieldException:
            return ""
        except MalformedRuleException:
            return ""

    def serialize_file(self, name, level):
        count = 0
        with open(name, "w") as file:
            write_file_header(file, level)
            for rule in self.rules:
                try:
                    serialized_rule = str(rule)
                    if rule.sigma_level == level:
                        file.write(serialized_rule + "\n")
                        count = count + 1
                except MalformedRuleException:
                    continue
            file.close()
        return count

    def finalize(self):
        count_critical = self.serialize_file("uberAgent-ESA-am-sigma-proc-creation-critical.conf", "critical")
        count_high = self.serialize_file("uberAgent-ESA-am-sigma-proc-creation-high.conf", "high")
        count_low = self.serialize_file("uberAgent-ESA-am-sigma-proc-creation-low.conf", "low")
        count_medium = self.serialize_file("uberAgent-ESA-am-sigma-proc-creation-medium.conf", "medium")
        print("Generated {} activity monitoring rules..".format(len(self.rules)))
        print(
            "This includes {} critical rules, {} high rules, {} medium rules and {} low rules..".format(count_critical,
                                                                                                        count_high,
                                                                                                        count_medium,
                                                                                                        count_low))

    def generateTypedValueNode(self, node):
        raise IgnoreTypedModifierException()

    def generateMapItemTypedNode(self, fieldname, value):
        raise IgnoreTypedModifierException()

    def generateMapItemListNode(self, key, value):
        return "(" + (" or ".join([self.mapWildcard % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateMapItemNode(self, node):
        fieldname, value = node
        transformed_fieldname = self.fieldNameMapping(fieldname, value)

        if value is None:
            return self.nullExpression % (transformed_fieldname,)

        has_wildcard = re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", self.generateNode(value))

        if "," in self.generateNode(value) and not has_wildcard:
            return self.mapListValueExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif self.mapListsSpecialHandling == False and type(value) in (
                str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if has_wildcard:
                return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
            else:
                return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif has_wildcard:
            return self.mapWildcard % (transformed_fieldname, self.generateNode(value))
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def cleanValue(self, val):
        if not isinstance(val, str):
            return str(val)

        # Single backlashes which are not in front of * or ? are doubled
        val = re.sub(r"(?<!\\)\\(?!(\\|\*|\?))", r"\\\\", val)

        # Replace _ with \_ because _ is a sql wildcard
        val = re.sub(r'_', r'\_', val)

        # Replace % with \% because % is a sql wildcard
        val = re.sub(r'%', r'\%', val)

        # Replace " with \" because " is a string literal symbol and must be escaped
        val = re.sub(r'"', r'\"', val)

        # Replace * with %, if even number of backslashes (or zero) in front of *
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\*", r"\1%", val)

        # Replace ? with _, if even number of backslashes (or zero) in front of ?
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\?", r"\1_", val)
        return val
