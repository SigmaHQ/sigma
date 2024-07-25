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


def load_fields_json(name: str):
    data_ng = {}
    file_path = os.path.abspath(os.path.dirname(__file__)) + "/" + name
    with open(file_path, "r", encoding="UTF-8") as file:
        json_dict = json.load(file)

    # build logsource
    for product in json_dict["sigma"]:
        l_product = None if product == "none" else product
        common = json_dict["sigma"][product]["common"]
        addon = json_dict["sigma"][product]["addon"]
        for key in json_dict["sigma"][product]["specific"]:
            fields = json_dict["sigma"][product]["specific"][key]
            # need to keep [] to bypass field name test
            if len(fields) > 0:
                fields += common

            if key in addon:
                fields += addon[key]

            if "Hashes" in fields or "Hash" in fields:
                fields += [
                    "md5",
                    "sha1",
                    "sha256",
                    "Imphash",
                ]

            try:
                category, service = key.split("§")
            except:
                print(f"can not split {key}")
                raise

            l_category = None if category == "none" else category
            l_service = None if service == "none" else service
            data_ng[
                SigmaLogSource(
                    product=l_product, category=l_category, service=l_service
                )
            ] = fields

    return data_ng


if __name__ == "__main__":
    init(autoreset=True)
    # load field name information
    fieldname_dict = load_fields_json("logsource.json")

    # Run the tests
    unittest.main()
