#!/usr/bin/env python3
"""
Checks for logsource or fieldname errors on all rules

Run using the command
# python test_logsource.py
"""

import os
import unittest
from colorama import init
from colorama import Fore
import json
from sigma.collection import SigmaCollection
from sigma.rule import SigmaLogSource, SigmaDetectionItem


class TestRules(unittest.TestCase):
    path_to_rules = [
        "rules",
        "rules-emerging-threats",
        "rules-placeholder",
        "rules-threat-hunting",
        "rules-compliance",
    ]
    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)

    #
    # test functions
    #

    # class FieldnameLogsourceIssue(SigmaValidationIssue): Usage of invalid field name in the log source

    def test_logsource_value(self):
        faulty_rules = []

        for rule in self.rule_collection:
            if not rule.logsource in fieldname_dict.keys():
                faulty_rules.append(rule.source)
                print(
                    Fore.RED
                    + "Rule {} has the unknown logsource product/category/service ({}/{}/{})".format(
                        rule.source,
                        rule.logsource.product,
                        rule.logsource.category,
                        rule.logsource.service,
                    )
                )

        self.assertEqual(
            faulty_rules,
            [],
            Fore.RED + "There are rules with non-conform 'logsource' values.",
        )

    def test_fieldname_case(self):
        def check_name(logsource, name):
            if name and not name in fieldname_dict[logsource]:
                return True
            else:
                return False

        files_with_fieldname_issues = []

        for rule in self.rule_collection:
            if (
                rule.logsource in fieldname_dict.keys()
                and len(fieldname_dict[rule.logsource]) > 0
            ):
                for detection in rule.detection.detections.values():
                    for item in detection.detection_items:
                        if isinstance(item, SigmaDetectionItem):
                            if check_name(rule.logsource, item.field):
                                files_with_fieldname_issues.append(rule.source)
                                print(
                                    Fore.RED
                                    + "Rule {} has the invalid field <{}>".format(
                                        rule.source, item.field
                                    )
                                )
                        else:
                            for sub_item in item.detection_items:
                                if check_name(rule.logsource, sub_item.field):
                                    files_with_fieldname_issues.append(rule.source)
                                    print(
                                        Fore.RED
                                        + "Rule {} has the invalid field <{}>".format(
                                            rule.source, sub_item.field
                                        )
                                    )

        self.assertEqual(
            files_with_fieldname_issues,
            [],
            Fore.RED
            + "There are rule files which contains unknown field or with cast error",
        )


def load_fields_json(json_name: str):
    field_info = {}
    common_info={}
    addon_info= {}

    file_path = os.path.abspath(os.path.dirname(__file__)) + "/" + json_name
    with open(file_path, "r", encoding="UTF-8") as file:
        json_dict = json.load(file)

    for key in json_dict["common"]:
        info=json_dict["common"][key]
        logsource = SigmaLogSource(product=info["product"], category=info["category"], service=info["service"])
        common_info[logsource]= info["data"]

    for key in json_dict["addon"]:
        info=json_dict["addon"][key]
        logsource = SigmaLogSource(product=info["product"], category=info["category"], service=info["service"])
        addon_info[logsource]= info["data"]

    for key in json_dict["field"]:
        info=json_dict["field"][key]
        logsource = SigmaLogSource(product=info["product"], category=info["category"], service=info["service"])
        field_info[logsource] = info["data"]

        if len(info["data"]) > 0:
            if logsource.product and SigmaLogSource(product=logsource.product) in common_info:
                field_info[logsource] += common_info[ SigmaLogSource(product=logsource.product)]
            if logsource in addon_info:
                field_info[logsource] += addon_info[logsource]
            if "Hashes" in info["data"] or "Hash" in info["data"]:
                field_info[logsource]+= ["md5","sha1","sha256","Imphash"]
 
    return field_info


if __name__ == "__main__":
    init(autoreset=True)
    # load field name information
    fieldname_dict = load_fields_json("logsource.json")

    # Run the tests
    unittest.main()
