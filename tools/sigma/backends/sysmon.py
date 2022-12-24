import re

import sigma
from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.mixins import MultiRuleOutputMixin

from .exceptions import NotSupportedError


class SysmonConfigBackend(SingleTextQueryBackend, MultiRuleOutputMixin):
    identifier = "sysmon"
    active = True
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "(%s)"
    config_required = True
    INCLUDE = "include"
    EXCLUDE = "exclude"
    conditionDict = {
        "startswith": "begin with",
        "endswith": "end with",
        "all": "contains all"
    }

    def __init__(self, *args, **kwargs):
        self.table = None
        self.logsource = None
        self.allowedSource = {
            "process_creation": "ProcessCreate"
        }
        self.eventidTagMapping = {
            1: "ProcessCreate",
            4799: "ProcessCreate",
            2: "FileCreateTime",
            3: "NetworkConnect",
            5: "ProcessTerminate",
            6: "DriverLoad",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            9: "RawAccessRead",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryEvent",
            13: "RegistryEvent",
            14: "RegistryEvent",
            15: "FileCreateStreamHash",
            17: "PipeEvent",
            18: "PipeEvent",
            19: "WmiEvent",
            20: "WmiEvent",
            21: "WmiEvent",
            22: "DNSQuery",
            257: "DNSQuery",
            23: "FileDelete"
        }
        self.allowedCondCombinations = {
            'single': [
                [4],
                [1, 4],
                [2, 4],
            ],
            'multi': [
                [1, 2, 4],
            ],
            "exclude": [
                [1, 3, 4],
                [2, 3, 4]
            ],
            # "multi-exclude": [
            #     [1, 2, 3, 4]
            # ]
        }
        return super().__init__(*args, **kwargs)

    def cleanValue(self, value):
        val = re.sub("[*]", "", value)
        return val

    def mapFiledValue(self, field, value):
        condition = None
        any_selector = "contains any"
        if "|" in field:
            field, *pipes = field.split("|")
            if len(pipes) == 1:
                modifier = pipes[0]
                if modifier in self.conditionDict:
                    condition = self.conditionDict[modifier]
                if modifier == "all":
                    any_selector = "contains all"
            else:
                raise NotImplementedError("not implemented condition")
        if isinstance(value, list) and len(value) > 1:
            condition = any_selector
            value = ";".join(value)
        elif "*" in value:
            if value.startswith("*") and value.endswith("*"):
                condition = "contains"
            elif value.startswith("*"):
                condition = "end with"
            elif value.endswith("*"):
                condition = "begin with"
            else:
                condition = "contains"

        if condition:
            field_str = '<{field} condition="{condition}">{value}</{field}>'.format(field=field,
                                                                                    condition=condition,
                                                                                    value=self.cleanValue(value))
        else:
            field_str = '<{field}>{value}</{field}>'.format(field=field, value=self.cleanValue(value))

        return field_str

    def createRule(self, selections):
        fields_list = []
        table = None
        for field, value in selections.items():
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            if field == "EventID":
                try:
                    table = self.eventidTagMapping[value]
                except KeyError:
                    table = self.eventidTagMapping[1]
            else:
                created_field_value = self.mapFiledValue(field, value)
                fields_list.append(created_field_value)
        fields_list_filtered = [item for item in fields_list if item]
        if any(fields_list_filtered):
            rule = '''\n\t\t<Rule name="{rule_name}" groupRelation="and">\n\t\t\t{fields}\n\t\t</Rule>'''.format(rule_name=self.rule_name, fields="\n\t\t\t".join(["{}".format(item) for item in fields_list_filtered]))
            t = table if table else self.table
            return rule, t
        else:
            return None, None

    def createRuleGroup(self, condition_objects, condition, match_type="include"):
        rules = None
        rules_selections = [item for item in condition_objects if item.type == 4]
        if len(rules_selections) == 1:
            rule, table = self.createRule(self.detection.get(rules_selections[0].matched))
            rules = {match_type: {table: rule}}
        else:
            if "or" in condition.lower():
                result = {}
                for selection_object in rules_selections:
                    rule, table = self.createRule(self.detection.get(selection_object.matched))
                    if result.get(table):
                        result[table].append(rule)
                    else:
                        result[table] = [rule]
                result = {table_name: "\n\t\t".join(rules_list) for table_name, rules_list in result.items()}
                rules = {match_type: result}
            elif "and" in condition.lower():
                rules_dict = {}
                for selection_object in rules_selections:
                    rules_dict.update(self.detection.get(selection_object.matched))
                rule, table = self.createRule(rules_dict)
                rules = {match_type: {table: rule}}
        if rules:
            rules_result = []
            for match, tables in rules.items():
                for table, rules in tables.items():
                    category_comment = '\n<!--Insert This Rule in <{} onmatch="{}"> section -->\n{}'.format(table, match,
                                                                                                            "".join(rules))
                    rules_result.append(category_comment)
            return "".join(rules_result)
        else:
            raise NotSupportedError("Couldn't create rule with current condition.")

    def createMultiRuleGroup(self, conditions):
        conditions_id = "".join([str(item.type) for item in conditions])
        or_index = conditions_id.index("2")
        sorted_conditions = [conditions[:or_index], conditions[or_index+1:]]
        if sorted_conditions:
            result = ""
            for rule_condition in sorted_conditions:
                rule = self.createRuleGroup(condition_objects=rule_condition, condition=" ".join([item.matched for item in rule_condition]))
                result += "{}\n".format(rule)
            return result
        else:
            raise NotSupportedError("Not implemented condition.")

    def createExcludeRuleGroup(self, conditions):
        conditions_id = "".join([str(item.type) for item in conditions])
        condition = self.detection.get("condition")
        sorted_conditions = None
        if "and not" in condition.lower():
            andnot_index = conditions_id.index("13")
            sorted_conditions = [(conditions[:andnot_index], self.INCLUDE), ([item for item in conditions if item.type != 3], self.EXCLUDE)]
        elif "or not" in condition.lower():
            ornot_index = conditions_id.index("23")
            sorted_conditions = [(conditions[:ornot_index], self.INCLUDE), (conditions[ornot_index + 2:], self.EXCLUDE)]
        if sorted_conditions:
            result = ""
            for rule_condition in sorted_conditions:
                rule = self.createRuleGroup(condition_objects=rule_condition[0], condition=" ".join([item.matched for item in rule_condition[0]]), match_type=rule_condition[1])
                result += "{}\n".format(rule)
            return result

    def checkRuleCondition(self, condtokens):
        if len(condtokens) == 1:
            conditions = [item for item in condtokens[0].tokens]
            conditions_combination = list(set([item.type for item in conditions]))
            for rule_type, combinations in self.allowedCondCombinations.items():
                for combination in combinations:
                    if sorted(conditions_combination) == sorted(combination):
                        return rule_type, conditions
            else:
                raise NotSupportedError("Not supported condition.")
        else:
            raise NotSupportedError("Not supported condition.")

    def createTableFromLogsource(self):
        if self.logsource.get("product", "") != "windows":
            raise NotSupportedError(
                "Not supported logsource. Should be product `windows`.")
        for item in self.logsource.values():
            if item.lower() in self.allowedSource.keys():
                self.table = self.allowedSource.get(item.lower())
                break
        else:
            self.table = "ProcessCreate"

    def checkDetection(self):
        for selection_name, value in self.detection.items():
            if isinstance(value, list):
                raise NotSupportedError("Keywords are not supported in sysmon backend.")


    def generate(self, sigmaparser):
        sysmon_rule = None
        title = sigmaparser.parsedyaml.get("title", "")
        author = sigmaparser.parsedyaml.get("author", {})
        self.rule_name = "{} by {}".format(title, author)
        self.detection = sigmaparser.parsedyaml.get("detection", {})
        self.checkDetection()
        self.logsource = sigmaparser.parsedyaml["logsource"]
        self.createTableFromLogsource()
        rule_type, conditions = self.checkRuleCondition(sigmaparser.condtoken)
        if rule_type == "single":
            sysmon_rule = self.createRuleGroup(conditions, self.detection.get("condition"))
        elif rule_type == "multi":
            sysmon_rule = self.createMultiRuleGroup(conditions)
        elif rule_type == "exclude":
            sysmon_rule = self.createExcludeRuleGroup(conditions)

        if sysmon_rule:
            rulegroup_comment = '<!--RuleGroup groupRelation should be `or` <RuleGroup groupRelation="or"> -->'
            return "{}\n{}".format(rulegroup_comment, sysmon_rule)