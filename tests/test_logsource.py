#!/usr/bin/env python3
"""
Checks for logsource or fieldname errors on all rules

Run using the command
# python test_logsource.py
"""

import os
import unittest
import yaml
from colorama import init
from colorama import Fore
import json


class TestRules(unittest.TestCase):
    path_to_rules_ = [
        "rules",
        "rules-emerging-threats",
        "rules-placeholder",
        "rules-threat-hunting",
        "rules-compliance",
    ]
    path_to_rules = []
    for path_ in path_to_rules_:
        path_to_rules.append(
            os.path.join(os.path.dirname(os.path.realpath(__name__)), path_)
        )

    # Helper functions
    def yield_next_rule_file_path(self, path_to_rules: list) -> str:
        for path_ in path_to_rules:
            for root, _, files in os.walk(path_):
                for file in files:
                    if file.endswith(".yml"):
                        yield os.path.join(root, file)

    def get_rule_yaml(self, file_path: str) -> dict:
        data = []

        with open(file_path, encoding="utf-8") as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)

        return data

    def get_rule_part(self, file_path: str, part_name: str):
        yaml_dicts = self.get_rule_yaml(file_path)
        for yaml_part in yaml_dicts:
            if part_name in yaml_part.keys():
                return yaml_part[part_name]

        return None

    def get_detection_field(self, detection: dict):
        data = []

        def get_field_name(selection: dict):
            name = []
            for field in selection:
                if field == "|all":
                    continue
                elif "|" in field:
                    name.append(field.split("|")[0])
                else:
                    name.append(field)
            return name

        for search_identifier in detection:
            if isinstance(detection[search_identifier], dict):
                data += get_field_name(detection[search_identifier])
            if isinstance(detection[search_identifier], list):
                for list_value in detection[search_identifier]:
                    if isinstance(list_value, dict):
                        data += get_field_name(list_value)

        return data

    def full_logsource(self, logsource: dict) -> dict:
        data = {}

        data["product"] = (
            logsource["product"] if "product" in logsource.keys() else None
        )
        data["category"] = (
            logsource["category"] if "category" in logsource.keys() else None
        )
        data["service"] = (
            logsource["service"] if "service" in logsource.keys() else None
        )

        return data

    def exist_logsource(self, logsource: dict) -> bool:
        # Check New product
        if logsource["product"]:
            if logsource["product"] in fieldname_dict.keys():
                product = logsource["product"]
            else:
                return False
        else:
            product = "empty"

        if (
            logsource["category"]
            and logsource["category"] in fieldname_dict[product]["category"].keys()
        ):
            return True
        elif (
            logsource["service"]
            and logsource["service"] in fieldname_dict[product]["service"].keys()
        ):
            return True
        elif logsource["category"] == None and logsource["service"] == None:
            return True  # We known the product but there are no category or service

        return False

    def get_logsource(self, logsource: dict) -> list:
        data = None

        product = (
            logsource["product"]
            if logsource["product"] in fieldname_dict.keys()
            else "empty"
        )

        if (
            logsource["category"]
            and logsource["category"] in fieldname_dict[product]["category"].keys()
        ):
            data = fieldname_dict[product]["category"][logsource["category"]]
        elif (
            logsource["service"]
            and logsource["service"] in fieldname_dict[product]["service"].keys()
        ):
            data = fieldname_dict[product]["service"][logsource["service"]]
        elif logsource["category"] == None and logsource["service"] == None:
            data = fieldname_dict[product]["empty"]

        return data

    def not_commun(self, logsource: dict, data: list) -> bool:
        product = (
            logsource["product"]
            if logsource["product"] in fieldname_dict.keys()
            else "empty"
        )

        if fieldname_dict[product]["common"] == data:
            return False
        else:
            return True

    #
    # test functions
    #
    def test_invalid_logsource_attributes(self):
        faulty_rules = []
        valid_logsource = [
            "category",
            "product",
            "service",
            "definition",
        ]

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            if not logsource:
                print(Fore.RED + "Rule {} has no 'logsource'.".format(file))
                faulty_rules.append(file)
                continue
            valid = True
            for key in logsource:
                if key not in valid_logsource:
                    print(
                        Fore.RED
                        + "Rule {} has a logsource with an invalid field ({})".format(
                            file, key
                        )
                    )
                    valid = False
                elif not isinstance(logsource[key], str):
                    print(
                        Fore.RED
                        + "Rule {} has a logsource with an invalid field type ({})".format(
                            file, key
                        )
                    )
                    valid = False
            if not valid:
                faulty_rules.append(file)

        self.assertEqual(
            faulty_rules,
            [],
            Fore.RED
            + "There are rules with non-conform 'logsource' fields. Please check: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#log-source",
        )

    def test_logsource_value(self):
        faulty_rules = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            if logsource:
                full_logsource = self.full_logsource(logsource)
                if not self.exist_logsource(full_logsource):
                    faulty_rules.append(file)
                    print(
                        Fore.RED
                        + "Rule {} has the unknown logsource product/category/service ({}/{}/{})".format(
                            file,
                            full_logsource["product"],
                            full_logsource["category"],
                            full_logsource["service"],
                        )
                    )

        self.assertEqual(
            faulty_rules,
            [],
            Fore.RED + "There are rules with non-conform 'logsource' values.",
        )

    def test_fieldname_case(self):
        files_with_fieldname_issues = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            detection = self.get_rule_part(file_path=file, part_name="detection")

            if logsource and detection:
                full_logsource = self.full_logsource(logsource)
                list_valid = self.get_logsource(full_logsource)
                first_time = True

                if list_valid and self.not_commun(full_logsource, list_valid):
                    for field in self.get_detection_field(detection):
                        if not field in list_valid:
                            print(
                                Fore.RED
                                + "Rule {} has the invalid field <{}>".format(
                                    file, field
                                )
                            )
                            if first_time:
                                files_with_fieldname_issues.append(file)
                                first_time = False  # can be many error in the same rule

        self.assertEqual(
            files_with_fieldname_issues,
            [],
            Fore.RED
            + "There are rule files which contains unknown field or with cast error",
        )


def load_fields_json(name: str):
    data = {}

    file_path = os.path.abspath(os.path.dirname(__file__)) + "/" + name
    with open(file_path, "r") as file:
        json_dict = json.load(file)

    for product in json_dict["legit"]:
        data[product] = json_dict["legit"][product]

    for product in json_dict["addon"]:
        for category in json_dict["addon"][product]["category"]:
            data[product]["category"][category] += json_dict["addon"][product][
                "category"
            ][category]
        for service in json_dict["addon"][product]["service"]:
            data[product]["service"][service] += json_dict["addon"][product]["service"][
                service
            ]

    # We use some extracted hash
    # Add common field
    for product in data:
        for category in data[product]["category"]:
            # if "Hashes" in data[product]["category"][category]:
            #     data[product]["category"][category] += [
            #         "md5",
            #         "sha1",
            #         "sha256",
            #         "Imphash",
            #     ]
            # if (
            #     "Hash" in data[product]["category"][category]
            # ):  # Sysmon 15 create_stream_hash
            #     data[product]["category"][category] += [
            #         "md5",
            #         "sha1",
            #         "sha256",
            #         "Imphash",
            #     ]
            if "common" in data[product].keys():
                data[product]["category"][category] += data[product]["common"]
        for service in data[product]["service"]:
            if "common" in data[product].keys():
                data[product]["service"][service] += data[product]["common"]

    return data


if __name__ == "__main__":
    init(autoreset=True)
    # load field name information
    fieldname_dict = load_fields_json("logsource.json")

    # Run the tests
    unittest.main()
