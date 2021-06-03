#!/usr/bin/env python3
"""
Checks for noncompliance or common errors on all rules

Run using the command
# python -m unittest test_rules.py
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

        with open(file_path) as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)

        return data

    # Tests
    def test_confirm_extension_is_yml(self):
        files_with_incorrect_extensions = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            file_name_and_extension = os.path.splitext(file)
            if len(file_name_and_extension) == 2:
                extension = file_name_and_extension[1]
                if extension != ".yml":
                    files_with_incorrect_extensions.append(file)

        self.assertEqual(files_with_incorrect_extensions, [], Fore.RED + 
                        "There are rule files with extensions other than .yml")

    def test_legal_trademark_violations(self):
        files_with_legal_issues = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            with open(file, 'r') as fh:
                file_data = fh.read()
                for tm in self.TRADE_MARKS:
                    if tm in file_data:
                        files_with_legal_issues.append(file)

        self.assertEqual(files_with_legal_issues, [], Fore.RED + 
                        "There are rule files which contains a trademark or reference that doesn't comply with the respective trademark requirements - please remove the trademark to avoid legal issues")

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

    def test_duplicate_titles(self):
        def compare_detections(detection1:dict, detection2:dict) -> bool:

            # detections not the same length can't be the same
            if len(detection1) != len(detection2):
                return False

            for named_condition in detection1:
                # condition clause must be the same too 
                if named_condition == "condition":
                    if detection1["condition"] != detection2["condition"]:
                        return False
                    else:
                        continue

                # Named condition must exist in both rule files
                if named_condition not in detection2:
                    return False

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
            with open(file) as f:
                for line in f:
                    if re.search(r'.*EventID: (?:1|4688)\s*$', line) and file not in faulty_detections:
                        faulty_detections.append(file)

        self.assertEqual(faulty_detections, [], Fore.YELLOW + 
                         "There are rules still using Sysmon 1 or Event ID 4688. Please migrate to the process_creation category.")

    def test_missing_id(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            id = self.get_rule_part(file_path=file, part_name="id")
            if not id:
                print(Fore.YELLOW + "Rule {} has no field 'id'.".format(file))
                faulty_rules.append(file)
            elif len(id) != 36:
                print(Fore.YELLOW + "Rule {} has a malformed 'id' (not 36 chars).".format(file))
                faulty_rules.append(file)                

        self.assertEqual(faulty_rules, [], Fore.RED + 
                         "There are rules with missing or malformed 'id' fields. Create an id (e.g. here: https://www.uuidgenerator.net/version4) and add it to the reported rule(s).")
    
    def test_sysmon_rule_without_eventid(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            service = logsource.get('service', '')
            if service.lower() == 'sysmon':
                with open(file) as f:
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
            elif len(datefield) != 10:
                print(Fore.YELLOW + "Rule {} has a malformed 'date' (not 10 chars, should be YYYY/MM/DD).".format(file))
                faulty_rules.append(file)                

        self.assertEqual(faulty_rules, [], Fore.RED +
                         "There are rules with missing or malformed 'date' fields. (create one, e.g. date: 2019/01/14)")

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
        filename_pattern = re.compile('[a-z0-9_]{10,70}\.yml')
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            filename = os.path.basename(file)
            if not filename_pattern.match(filename) and not '_' in filename:
                print(Fore.YELLOW + "Rule {} has a file name that doesn't match our standard.".format(file))
                faulty_rules.append(file)     

        self.assertEqual(faulty_rules, [], Fore.RED + 
                         "There are rules with malformed file names (too short, too long, uppercase letters, a minus sign etc.). Please see the file names used in our repository and adjust your file names accordingly. The pattern for a valid file name is '[a-z0-9_]{10,70}\.yml' and it has to contain at least an underline character.")

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
            wrong_casing = []
            for word in title.split(" "):
                if word.islower() and not word.lower() in allowed_lowercase_words and not "." in word and not "/" in word and not word[0].isdigit():
                    wrong_casing.append(word)
            if len(wrong_casing) > 0:
                print(Fore.RED + "Rule {} has a title that has not title capitalization. Words: '{}'".format(file, ", ".join(wrong_casing)))
                faulty_rules.append(file)

        self.assertEqual(faulty_rules, [], Fore.RED + 
                         "There are rules with non-conform 'title' fields. Please check: https://github.com/Neo23x0/sigma/wiki/Rule-Creation-Guide#title")

    def test_invalid_logsource_attributes(self):
        faulty_rules = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            for key in logsource:
                if key.lower() not in ['category', 'product', 'service', 'definition']:
                    print(Fore.RED + "Rule {} has a logsource with an invalid field ({})".format(file, key))

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
    
    # Combine all IDs to a big tag list
    return ["attack." + item for item in MITRE_TECHNIQUES + MITRE_TECHNIQUE_NAMES + list(MITRE_PHASE_NAMES) + MITRE_GROUPS + MITRE_TOOLS]


if __name__ == "__main__":
    init(autoreset=True)
    # Get Current Data from MITRE ATT&CK®
    MITRE_ALL = get_mitre_data()
    # Run the tests
    unittest.main()
