#!/usr/bin/env python3
"""
Checks for noncompliance or common errors on all rules

Run using the command
# python test_rules.py
"""

import os
import unittest
import yaml
import re
from attackcti import attack_client
from colorama import init
from colorama import Fore

class TestRules(unittest.TestCase):
    MITRE_TECHNIQUE_NAMES = ["process_injection", "signed_binary_proxy_execution", "process_injection"] # incomplete list
    MITRE_TACTICS = ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration", "command_and_control", "impact", "launch"]
    # Don't use trademarks in rules - they require non-ASCII characters to be used on we don't want them in our rules
    TRADE_MARKS = {"MITRE ATT&CK", "ATT&CK"}

    path_to_rules = "rules"

    # Helper functions
    def yield_next_rule_file_path(self, path_to_rules:str) -> str:
        for root, _, files in os.walk(path_to_rules):
            for file in files:
                yield os.path.join(root, file)

    def get_rule_part(self, file_path:str, part_name:str):
        yaml_dicts = self.get_rule_yaml(file_path)
        for yaml_part in yaml_dicts:
            if part_name in yaml_part.keys():
                return yaml_part[part_name]

        return None

    def get_rule_yaml(self, file_path:str) -> dict:
        data = []

        with open(file_path,encoding='utf-8') as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)

        return data

    # Tests
    # def test_confirm_extension_is_yml(self):
        # files_with_incorrect_extensions = []

        # for file in self.yield_next_rule_file_path(self.path_to_rules):
            # file_name_and_extension = os.path.splitext(file)
            # if len(file_name_and_extension) == 2:
                # extension = file_name_and_extension[1]
                # if extension != ".yml":
                    # files_with_incorrect_extensions.append(file)

        # self.assertEqual(files_with_incorrect_extensions, [], Fore.RED +
                        # "There are rule files with extensions other than .yml")

    def test_legal_trademark_violations(self):
        files_with_legal_issues = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            with open(file, 'r',encoding='utf-8') as fh:
                file_data = fh.read()
                for tm in self.TRADE_MARKS:
                    if tm in file_data:
                        files_with_legal_issues.append(file)

        self.assertEqual(files_with_legal_issues, [], Fore.RED +
                        "There are rule files which contains a trademark or reference that doesn't comply with the respective trademark requirements - please remove the trademark to avoid legal issues")

    def test_optional_tags(self):
        files_with_incorrect_tags = []
        tags_pattern = re.compile(r"cve\.\d+\.\d+|attack\.t\d+\.*\d*|attack\.[a-z_]+|car\.\d{4}-\d{2}-\d{3}")
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            tags = self.get_rule_part(file_path=file, part_name="tags")
            if tags:
                for tag in tags:
                    if tags_pattern.match(tag) == None:
                        print(Fore.RED + "Rule {} has the invalid tag <{}>".format(file, tag))
                        files_with_incorrect_tags.append(file)

        self.assertEqual(files_with_incorrect_tags, [], Fore.RED +
                         "There are rules with incorrect/unknown MITRE Tags. (please inform us about new tags that are not yet supported in our tests) and check the correct tags here: https://attack.mitre.org/ ")

    def test_confirm_correct_mitre_tags(self):
        files_with_incorrect_mitre_tags = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            tags = self.get_rule_part(file_path=file, part_name="tags")
            if tags:
                for tag in tags:
                    if tag not in MITRE_ALL and tag.startswith("attack."):
                        print(Fore.RED + "Rule {} has the following incorrect tag {}".format(file, tag))
                        files_with_incorrect_mitre_tags.append(file)

        self.assertEqual(files_with_incorrect_mitre_tags, [], Fore.RED +
                         "There are rules with incorrect/unknown MITRE Tags. (please inform us about new tags that are not yet supported in our tests) and check the correct tags here: https://attack.mitre.org/ ")

    def test_duplicate_tags(self):
        files_with_incorrect_mitre_tags = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            tags = self.get_rule_part(file_path=file, part_name="tags")
            if tags:
                known_tags = []
                for tag in tags:
                    if tag in known_tags:
                        print(Fore.RED + "Rule {} has the duplicate tag {}".format(file, tag))
                        files_with_incorrect_mitre_tags.append(file)
                    else:
                        known_tags.append(tag)

        self.assertEqual(files_with_incorrect_mitre_tags, [], Fore.RED +
                         "There are rules with duplicate tags")

    def test_look_for_duplicate_filters(self):
        def check_list_or_recurse_on_dict(item, depth:int) -> None:
            if type(item) == list:
                check_if_list_contain_duplicates(item, depth)
            elif type(item) == dict and depth <= MAX_DEPTH:
                for sub_item in item.values():
                    check_list_or_recurse_on_dict(sub_item, depth + 1)

        def check_if_list_contain_duplicates(item:list, depth:int) -> None:
            try:
                if len(item) != len(set(item)):
                    print(Fore.RED + "Rule {} has duplicate filters".format(file))
                    files_with_duplicate_filters.append(file)
            except:
                # unhashable types like dictionaries
                for sub_item in item:
                    if type(sub_item) == dict and depth <= MAX_DEPTH:
                        check_list_or_recurse_on_dict(sub_item, depth + 1)

        MAX_DEPTH = 3
        files_with_duplicate_filters = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path=file, part_name="detection")
            check_list_or_recurse_on_dict(detection, 1)

        self.assertEqual(files_with_duplicate_filters, [], Fore.RED +
                         "There are rules with duplicate filters")

    def test_field_name_with_space(self):
        def key_iterator(fields, faulty):
            for key, value in fields.items():
                if " " in key:
                    faulty.append(key)
                    print(Fore.YELLOW + "Rule {} has a space in field name ({}).".format(file, key))
                if type(value) == dict:
                    key_iterator(value, faulty)

        faulty_fieldnames = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path = file, part_name = "detection")
            key_iterator(detection, faulty_fieldnames)

        self.assertEqual(faulty_fieldnames, [], Fore.RED +
                "There are rules with an unsupported field name. Spaces are not allowed. (Replace space with an underscore character '_' )")

    def test_single_named_condition_with_x_of_them(self):
        faulty_detections = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            yaml = self.get_rule_yaml(file_path = file)
            detection = self.get_rule_part(file_path = file, part_name = "detection")

            has_them_in_condition = "them" in detection["condition"]
            has_only_one_named_condition = len(detection) == 2
            not_multipart_yaml_file = len(yaml) == 1

            if has_them_in_condition and \
                has_only_one_named_condition and \
                    not_multipart_yaml_file:
                faulty_detections.append(file)

        self.assertEqual(faulty_detections, [], Fore.RED +
                         "There are rules using '1/all of them' style conditions but only have one condition")

    def test_all_of_them_condition(self):
        faulty_detections = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path = file, part_name = "detection")

            if "all of them" in detection["condition"]:
                faulty_detections.append(file)

        self.assertEqual(faulty_detections, [], Fore.RED +
                         "There are rules using 'all of them'. Better use e.g. 'all of selection*' instead (and use the 'selection_' prefix as search-identifier).")

    def test_duplicate_detections(self):
        def compare_detections(detection1:dict, detection2:dict) -> bool:

            # detections not the same count can't be the same
            if len(detection1) != len(detection2):
                return False

            for named_condition in detection1:
                #don't check timeframes
                if named_condition == "timeframe":
                    continue

                # condition clause must be the same too
                if named_condition == "condition":
                    if detection1["condition"] != detection2["condition"]:
                        return False
                    else:
                        continue

                # Named condition must exist in both rule files
                if named_condition not in detection2:
                    return False

                #can not be the same  if len is not equal
                if len(detection1[named_condition]) != len(detection2[named_condition]):
                    return False


                for condition in detection1[named_condition]:
                    if type(condition) != str:
                        return False

                    if condition not in detection2[named_condition]:
                        return False

                    condition_value1 = detection1[named_condition][condition]
                    condition_value2 = detection2[named_condition][condition]
                    if condition_value1 != condition_value2:
                        return False

            return True

        faulty_detections = []
        files_and_their_detections = {}

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path = file, part_name = "detection")
            logsource = self.get_rule_part(file_path = file, part_name = "logsource")
            detection["logsource"] = {}
            detection["logsource"].update(logsource)
            yaml = self.get_rule_yaml(file_path = file)

            is_multipart_yaml_file = len(yaml) != 1
            if is_multipart_yaml_file:
                continue

            for key in files_and_their_detections:
                if compare_detections(detection, files_and_their_detections[key]):
                    faulty_detections.append((key, file))

            files_and_their_detections[file] = detection

        self.assertEqual(faulty_detections, [], Fore.YELLOW +
                         "There are rule files with exactly the same detection logic.")

    def test_source_eventlog(self):
        faulty_detections = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path = file, part_name = "detection")
            detection_str = str(detection).lower()
            if "'source': 'eventlog'" in detection_str:
                faulty_detections.append(file)

        self.assertEqual(faulty_detections, [], Fore.YELLOW +
                         "There are detections with 'Source: Eventlog'. This does not add value to the detection.")

    def test_event_id_instead_of_process_creation(self):
        faulty_detections = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            with open(file,encoding='utf-8') as f:
                for line in f:
                    if re.search(r'.*EventID: (?:1|4688)\s*$', line) and file not in faulty_detections:
                        faulty_detections.append(file)

        self.assertEqual(faulty_detections, [], Fore.YELLOW +
                         "There are rules still using Sysmon 1 or Event ID 4688. Please migrate to the process_creation category.")

    def test_missing_id(self):
        faulty_rules = []
        dict_id = {}
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            id = self.get_rule_part(file_path=file, part_name="id")
            if not id:
                print(Fore.YELLOW + "Rule {} has no field 'id'.".format(file))
                faulty_rules.append(file)
            elif len(id) != 36:
                print(Fore.YELLOW + "Rule {} has a malformed 'id' (not 36 chars).".format(file))
                faulty_rules.append(file)
            elif id in dict_id.keys():
                print(Fore.YELLOW + "Rule {} has the same 'id' than {} must be unique.".format(file,dict_id[id]))
                faulty_rules.append(file)
            else:
                dict_id[id] = file

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with missing or malformed 'id' fields. Create an id (e.g. here: https://www.uuidgenerator.net/version4) and add it to the reported rule(s).")

    def test_optional_related(self):
        faulty_rules = []
        valid_type = [
            "derived",
            "obsoletes",
            "merged",
            "renamed",
            "similar"
            ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            related_lst = self.get_rule_part(file_path=file, part_name="related")
            if related_lst:
                # it exists but isn't a list
                if not isinstance(related_lst, list):
                    print(Fore.YELLOW + "Rule {} has a 'related' field that isn't a list.".format(file))
                    faulty_rules.append(file)
                else:
                    # should probably test if we have only 'id' and 'type' ...
                    type_ok = True
                    for ref in related_lst:
                        id_str = ref['id']
                        type_str = ref['type']
                        if not type_str in valid_type:
                           type_ok = False
                    #Only add one time if many bad type in the same file
                    if type_ok == False:
                        print(Fore.YELLOW + "Rule {} has a 'related/type' invalid value.".format(file))
                        faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed optional 'related' fields. (check https://github.com/SigmaHQ/sigma/wiki/Specification)")

    def test_sysmon_rule_without_eventid(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            if logsource:
                service = logsource.get('service', '')
                if service.lower() == 'sysmon':
                    with open(file,encoding='utf-8') as f:
                        found = False
                        for line in f:
                            if re.search(r'.*EventID:.*$', line):  # might be on a single line or in multiple lines
                                found = True
                                break
                        if not found:
                            faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules using sysmon events but with no EventID specified")

    def test_missing_date(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            datefield = self.get_rule_part(file_path=file, part_name="date")
            if not datefield:
                print(Fore.YELLOW + "Rule {} has no field 'date'.".format(file))
                faulty_rules.append(file)
            elif not isinstance(datefield, str):
                print(Fore.YELLOW + "Rule {} has a malformed 'date' (should be YYYY/MM/DD).".format(file))
                faulty_rules.append(file)
            elif len(datefield) != 10:
                print(Fore.YELLOW + "Rule {} has a malformed 'date' (not 10 chars, should be YYYY/MM/DD).".format(file))
                faulty_rules.append(file)
            elif datefield[4] != '/' or datefield[7] != '/':
                print(Fore.YELLOW + "Rule {} has a malformed 'date' (should be YYYY/MM/DD).".format(file))
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with missing or malformed 'date' fields. (create one, e.g. date: 2019/01/14)")

    def test_missing_description(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            descriptionfield = self.get_rule_part(file_path=file, part_name="description")
            if not descriptionfield:
                print(Fore.YELLOW + "Rule {} has no field 'description'.".format(file))
                faulty_rules.append(file)
            elif not isinstance(descriptionfield, str):
                print(Fore.YELLOW + "Rule {} has a 'description' field that isn't a string.".format(file))
                faulty_rules.append(file)
            elif len(descriptionfield) < 16:
                print(Fore.YELLOW + "Rule {} has a really short description. Please elaborate.".format(file))
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with missing or malformed 'description' field. (create one, e.g. description: Detects the suspicious behaviour of process XY doing YZ)")

    def test_optional_date_modified(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            modifiedfield = self.get_rule_part(file_path=file, part_name="modified")
            if modifiedfield:
                if not isinstance(modifiedfield, str):
                    print(Fore.YELLOW + "Rule {} has a malformed 'modified' (should be YYYY/MM/DD).".format(file))
                    faulty_rules.append(file)
                elif len(modifiedfield) != 10:
                    print(Fore.YELLOW + "Rule {} has a malformed 'modified' (not 10 chars, should be YYYY/MM/DD).".format(file))
                    faulty_rules.append(file)
                elif modifiedfield[4] != '/' or modifiedfield[7] != '/':
                    print(Fore.YELLOW + "Rule {} has a malformed 'modified' (should be YYYY/MM/DD).".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'modified' fields. (create one, e.g. date: 2019/01/14)")

    def test_optional_status(self):
        faulty_rules = []
        valid_status = [
            "stable",
            "test",
            "experimental",
            "deprecated",
            "unsupported"
            ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            status_str = self.get_rule_part(file_path=file, part_name="status")
            if status_str:
                if not status_str in valid_status:
                    print(Fore.YELLOW + "Rule {} has a invalid 'status' (check wiki).".format(file))
                    faulty_rules.append(file)
                elif status_str == "unsupported":
                    print(Fore.YELLOW + "Rule {} has the unsupported 'status', can not be in rules directory".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'status' fields. (check https://github.com/SigmaHQ/sigma/wiki/Specification)")

    def test_level(self):
        faulty_rules = []
        valid_level = [
            "informational",
            "low",
            "medium",
            "high",
            "critical",
            ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            level_str = self.get_rule_part(file_path=file, part_name="level")
            if not level_str:
                print(Fore.YELLOW + "Rule {} has no field 'level'.".format(file))
                faulty_rules.append(file)
            elif not level_str in valid_level:
                    print(Fore.YELLOW + "Rule {} has a invalid 'level' (check wiki).".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with missing or malformed 'level' fields. (check https://github.com/SigmaHQ/sigma/wiki/Specification)")

    def test_optional_fields(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            fields_str = self.get_rule_part(file_path=file, part_name="fields")
            if fields_str:
                # it exists but isn't a list
                if not isinstance(fields_str, list):
                    print(Fore.YELLOW + "Rule {} has a 'fields' field that isn't a list.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed optional 'fields' fields. (has to be a list of values even if it contains only a single value)")

    def test_optional_falsepositives_listtype(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            falsepositives_str = self.get_rule_part(file_path=file, part_name="falsepositives")
            if falsepositives_str:
                # it exists but isn't a list
                if not isinstance(falsepositives_str, list):
                    print(Fore.YELLOW + "Rule {} has a 'falsepositives' field that isn't a list.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed optional 'falsepositives' fields. (has to be a list of values even if it contains only a single value)")

    def test_optional_falsepositives_capital(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            fps = self.get_rule_part(file_path=file, part_name="falsepositives")
            if fps:
                for fp in fps:
                    # first letter should be capital
                    try:
                        if fp[0].upper() != fp[0]:
                            print(Fore.YELLOW + "Rule {} defines a falsepositive that does not start with a capital letter: '{}'.".format(file, fp))
                            faulty_rules.append(file)
                    except TypeError as err:
                        print("TypeError Exception for rule {}".format(file))
                        print("Error: {}".format(err))
                        print("Maybe you created an empty falsepositive item?")

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with false positives that don't start with a capital letter (e.g. 'unknown' should be 'Unknown')")

    def test_optional_falsepositives_blocked_content(self):
        faulty_rules = []
        banned_words = ["none", "pentest", "penetration test"]
        common_typos = ["unkown", "ligitimate", "legitim ", "legitimeate"]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            fps = self.get_rule_part(file_path=file, part_name="falsepositives")
            if fps:
                for fp in fps:
                    for typo in common_typos:
                        if fp == "Unknow" or typo in fp.lower():
                            print(Fore.YELLOW + "Rule {} defines a falsepositive with a common typo: '{}'.".format(file, typo))
                            faulty_rules.append(file)
                    for banned_word in banned_words:
                        if banned_word in fp.lower():
                            print(Fore.YELLOW + "Rule {} defines a falsepositive with an invalid reason: '{}'.".format(file, banned_word))
                            faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with invalid false positive definitions (e.g. Pentest, None or common typos)")

    # Upgrade Detection Rule License  1.1
    def test_optional_author(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            author_str = self.get_rule_part(file_path=file, part_name="author")
            if author_str:
                # it exists but isn't a string
                if not isinstance(author_str, str):
                    print(Fore.YELLOW + "Rule {} has a 'author' field that isn't a string.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'author' fields. (has to be a string even if it contains many author)")

    def test_optional_license(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            license_str = self.get_rule_part(file_path=file, part_name="license")
            if license_str:
                if not isinstance(license_str, str):
                    print(Fore.YELLOW + "Rule {} has a malformed 'license' (has to be a string).".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'license' fields. (has to be a string )")

    def test_optional_tlp(self):
        faulty_rules = []
        valid_tlp = [
            "WHITE",
            "GREEN",
            "AMBER",
            "RED",
            ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            tlp_str = self.get_rule_part(file_path=file, part_name="tlp")
            if tlp_str:
                # it exists but isn't a string
                if not isinstance(tlp_str, str):
                    print(Fore.YELLOW + "Rule {} has a 'tlp' field that isn't a string.".format(file))
                    faulty_rules.append(file)
                elif not tlp_str.upper() in valid_tlp:
                    print(Fore.YELLOW + "Rule {} has a 'tlp' field with not valid value.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed optional 'tlp' fields. (https://www.cisa.gov/tlp)")

    def test_optional_target(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            target = self.get_rule_part(file_path=file, part_name="target")
            if target:
                # it exists but isn't a list
                if not isinstance(target, list):
                    print(Fore.YELLOW + "Rule {} has a 'target' field that isn't a list.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'target' fields. (has to be a list of values even if it contains only a single value)")

    def test_references(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            references = self.get_rule_part(file_path=file, part_name="references")
            # Reference field doesn't exist
            # if not references:
                # print(Fore.YELLOW + "Rule {} has no field 'references'.".format(file))
                # faulty_rules.append(file)
            if references:
                # it exists but isn't a list
                if not isinstance(references, list):
                    print(Fore.YELLOW + "Rule {} has a references field that isn't a list.".format(file))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'references' fields. (has to be a list of values even if it contains only a single value)")

    def test_references_plural(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            reference = self.get_rule_part(file_path=file, part_name="reference")
            if reference:
                # it exists but in singular form
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with malformed 'references' fields. (has to be 'references' in plural form, not singular)")

    def test_file_names(self):
        faulty_rules = []
        name_lst = []
        filename_pattern = re.compile(r'[a-z0-9_]{10,70}\.yml')
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            filename = os.path.basename(file)
            if filename in name_lst:
                print(Fore.YELLOW + "Rule {} is a duplicate file name.".format(file))
                faulty_rules.append(file)
            elif filename[-4:] != ".yml":
                print(Fore.YELLOW + "Rule {} has a invalid extension (.yml).".format(file))
                faulty_rules.append(file)
            elif len(filename) > 74:
                print(Fore.YELLOW + "Rule {} has a file name too long >70.".format(file))
                faulty_rules.append(file)
            elif len(filename) < 14:
                print(Fore.YELLOW + "Rule {} has a file name too short <10.".format(file))
                faulty_rules.append(file)
            elif filename_pattern.match(filename) == None or not '_' in filename:
                print(Fore.YELLOW + "Rule {} has a file name that doesn't match our standard.".format(file))
                faulty_rules.append(file)
            name_lst.append(filename)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         r'There are rules with malformed file names (too short, too long, uppercase letters, a minus sign etc.). Please see the file names used in our repository and adjust your file names accordingly. The pattern for a valid file name is \'[a-z0-9_]{10,70}\.yml\' and it has to contain at least an underline character.')

    def test_title(self):
        faulty_rules = []
        allowed_lowercase_words = [
                'the',
                'for',
                'in',
                'with',
                'via',
                'on',
                'to',
                'without',
                'of',
                'through',
                'from',
                'by',
                'as',
                'a',
                'or',
                'at',
                'and',
                'an',
                'over',
                'new',
                ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            title = self.get_rule_part(file_path=file, part_name="title")
            if not title:
                print(Fore.RED + "Rule {} has no field 'title'.".format(file))
                faulty_rules.append(file)
                continue
            elif len(title) > 70:
                print(Fore.YELLOW + "Rule {} has a title field with too many characters (>70)".format(file))
                faulty_rules.append(file)
            if title.startswith("Detects "):
                print(Fore.RED + "Rule {} has a title that starts with 'Detects'".format(file))
                faulty_rules.append(file)
            if title.endswith("."):
                print(Fore.RED + "Rule {} has a title that ends with '.'".format(file))
                faulty_rules.append(file)
            wrong_casing = []
            for word in title.split(" "):
                if word.islower() and not word.lower() in allowed_lowercase_words and not "." in word and not "/" in word and not word[0].isdigit():
                    wrong_casing.append(word)
            if len(wrong_casing) > 0:
                print(Fore.RED + "Rule {} has a title that has not title capitalization. Words: '{}'".format(file, ", ".join(wrong_casing)))
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with non-conform 'title' fields. Please check: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#title")

    def test_title_in_first_line(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            yaml = self.get_rule_yaml(file)

            # skip multi-part yaml
            if len(yaml) > 1:
                continue

            # this propably is not the best way to check whether
            # title is the attribute given in the 1st line
            # (also assumes dict keeps the order from the input file)
            if list(yaml[0].keys())[0] != "title":
                print(Fore.RED + "Rule {} does not have its 'title' attribute in the first line".format(file))
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                        "There are rules without the 'title' attribute in their first line.")

    def test_invalid_logsource_attributes(self):
        faulty_rules = []
        valid_logsource = [
           'category',
           'product',
           'service',
           'definition',
           ]
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            if not logsource:
                print(Fore.RED + "Rule {} has no 'logsource'.".format(file))
                faulty_rules.append(file)
                continue
            valid = True
            for key in logsource:
                if key.lower() not in valid_logsource:
                    print(Fore.RED + "Rule {} has a logsource with an invalid field ({})".format(file, key))
                    valid = False
                elif not isinstance(logsource[key],str):
                    print(Fore.RED + "Rule {} has a logsource with an invalid field type ({})".format(file, key))
                    valid = False
            if not valid:
               faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with non-conform 'logsource' fields. Please check: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide#log-source")


    def test_selection_list_one_value(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path=file, part_name="detection")
            if detection:
                valid = True
                for key in detection:
                    if isinstance(detection[key],list):
                        if len(detection[key]) == 1 and not isinstance(detection[key][0],str): #rule with only list of Keywords term
                            print(Fore.RED + "Rule {} has the selection ({}) with a list of only 1 element in detection".format(file, key))
                            valid = False
                    if isinstance(detection[key],dict):
                        for sub_key in detection[key]:
                            if isinstance(detection[key][sub_key],list): #split in 2 if as get a error "int has not len()"
                                if len(detection[key][sub_key]) == 1:
                                    print (Fore.RED + "Rule {} has the selection ({}/{}) with a list of only 1 value in detection".format(file, key, sub_key))
                                    valid = False
                    if not valid:
                        faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED + "There are rules using list with only 1 element")

    def test_unused_selection(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path=file, part_name="detection")
            condition = detection["condition"]
            wildcard_selections = re.compile(r"\sof\s([\w\*]+)(?:$|\s|\))")

            # skip rules containing aggregations
            if type(condition) == list:
                continue

            for selection in detection:
                if selection == "condition":
                    continue
                if selection == "timeframe":
                    continue
                if selection in condition:
                    continue
                # find all wildcards in condition
                found = False
                for wildcard_selection in wildcard_selections.findall(condition):
                    # wildcard matches selection
                    if re.search(wildcard_selection.replace(r"*", r".*"), selection) is not None:
                        found = True
                        break
                # selection was not found in condition
                if not found:
                    print(Fore.RED + "Rule {} has an unused selection '{}'".format(file, selection))
                    faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED + "There are rules with unused selections")

    def test_all_value_modifier_single_item(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path=file, part_name="detection")
            if detection:
                for search_identifier in detection:
                    if isinstance(detection[search_identifier],dict):
                        for field in detection[search_identifier]:
                            if "|all" in field and not isinstance(detection[search_identifier][field],list):
                                print (Fore.RED + "Rule {} uses the 'all' modifier on a single item in selection ({}/{})".format(file, search_identifier, field))
                                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED + "There are rules with |all modifier only having one item. " +
        "Single item values are not allowed to have an all modifier as some back-ends cannot support it. " +
        "If you use it as a workaround to duplicate a field in a selection, use a new selection instead.")

    def test_field_user_localization(self):
        def checkUser(faulty_rules, dict):
            for key, value in dict.items():
                if "User" in key:
                    if type(value) == str:
                        if "AUTORI" in value or "AUTHORI" in value:
                            print("Localized user name '{}'.".format(value))
                            faulty_rules.append(file)

        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path=file, part_name="detection")
            for sel_key, sel_value in detection.items():
                if sel_key == "condition" or sel_key == "timeframe":
                    continue
                # single item selection
                if type(sel_value) == dict:
                    checkUser(faulty_rules, sel_value)
                if type(sel_value) == list:
                    # skip keyword selection
                    if type(sel_value[0]) != dict:
                        continue
                    # multiple item selection
                    for item in sel_value:
                        checkUser(faulty_rules, item)

        self.assertEqual(faulty_rules, [], Fore.RED + "There are rules that match using localized user accounts. Better employ a generic version such as:\n" +
            "User|contains: # covers many language settings\n" +
            "    - 'AUTHORI'\n" +
            "    - 'AUTORI'")



    def test_condition_operator_casesensitive(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
             detection = self.get_rule_part(file_path=file, part_name="detection")
             if detection:
                 valid = True
                 if isinstance(detection["condition"],str):
                     param = detection["condition"].split(' ')
                     for item in param:
                        if item.lower() == 'or' and not item == 'or':
                            valid = False
                        elif item.lower() == 'and' and not item == 'and':
                            valid = False
                        elif item.lower() == 'not' and not item == 'not':
                            valid = False
                        elif item.lower() == 'of' and not item == 'of':
                            valid = False
                     if not valid:
                         print(Fore.RED + "Rule {} has a invalid condition '{}' : 'or','and','not','of' are lowercase".format(file,detection["condition"]))
                         faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED + "There are rules using condition without lowercase operator")

def get_mitre_data():
    """
    Generate tags from live TAXI service to get up-to-date data
    """
    # Get ATT&CK information
    lift = attack_client()
    # Techniques
    MITRE_TECHNIQUES = []
    MITRE_TECHNIQUE_NAMES = []
    MITRE_PHASE_NAMES = set()
    MITRE_TOOLS = []
    MITRE_GROUPS = []
    # Techniques
    enterprise_techniques = lift.get_enterprise_techniques()
    for t in enterprise_techniques:
        MITRE_TECHNIQUE_NAMES.append(t['name'].lower().replace(' ', '_').replace('-', '_'))
        for r in t.external_references:
            if 'external_id' in r:
                MITRE_TECHNIQUES.append(r['external_id'].lower())
        if 'kill_chain_phases' in t:
            for kc in t['kill_chain_phases']:
                if 'phase_name' in kc:
                    MITRE_PHASE_NAMES.add(kc['phase_name'].replace('-','_'))
    # Tools / Malware
    enterprise_tools = lift.get_enterprise_tools()
    for t in enterprise_tools:
        for r in t.external_references:
            if 'external_id' in r:
                MITRE_TOOLS.append(r['external_id'].lower())
    enterprise_malware = lift.get_enterprise_malware()
    for m in enterprise_malware:
        for r in m.external_references:
            if 'external_id' in r:
                MITRE_TOOLS.append(r['external_id'].lower())
    # Groups
    enterprise_groups = lift.get_enterprise_groups()
    for g in enterprise_groups:
        for r in g.external_references:
            if 'external_id' in r:
                MITRE_GROUPS.append(r['external_id'].lower())

    # Debugging
    print("MITRE ATT&CK LIST LENGTHS: %d %d %d %d %d" % (len(MITRE_TECHNIQUES), len(MITRE_TECHNIQUE_NAMES), len(list(MITRE_PHASE_NAMES)), len(MITRE_GROUPS), len(MITRE_TOOLS)))

    # Combine all IDs to a big tag list
    return ["attack." + item for item in MITRE_TECHNIQUES + MITRE_TECHNIQUE_NAMES + list(MITRE_PHASE_NAMES) + MITRE_GROUPS + MITRE_TOOLS]


if __name__ == "__main__":
    init(autoreset=True)
    # Get Current Data from MITRE ATT&CK®
    MITRE_ALL = get_mitre_data()
    # Run the tests
    unittest.main()
