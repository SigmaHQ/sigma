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

class TestRules(unittest.TestCase):
    MITRE_TECHNIQUES = ["t1075", "t1189", "t1190", "t1200", "t1091", "t1193", "t1192", "t1194", "t1195", "t1199", "t1078", "t1155", "t1191", "t1059", "t1223", "t1196", "t1173", "t1106", "t1129", "t1203", "t1061", "t1118", "t1152", "t1168", "t1177", "t1170", "t1086", "t1121", "t1117", "t1085", "t1053", "t1064", "t1035", "t1218", "t1216", "t1153", "t1151", "t1072", "t1154", "t1127", "t1204", "t1047", "t1028", "t1220", "t1156", "t1015", "t1098", "t1182", "t1103", "t1138", "t1131", "t1197", "t1067", "t1176", "t1042", "t1109", "t1122", "t1136", "t1038", "t1157", "t1133", "t1044", "t1158", "t1179", "t1062", "t1183", "t1215", "t1159", "t1160", "t1152", "t1161", "t1168", "t1162", "t1037", "t1031", "t1128", "t1050", "t1137", "t1034", "t1150", "t1205", "t1013", "t1163", "t1164", "t1108", "t1060", "t1053", "t1180", "t1101", "t1058", "t1166", "t1023", "t1198", "t1165", "t1019", "t1209", "t1154", "t1078", "t1100", "t1084", "t1004", "t1134", "t1015", "t1182", "t1103", "t1138", "t1088", "t1038", "t1157", "t1068", "t1181", "t1044", "t1179", "t1183", "t1160", "t1050", "t1034", "t1150", "t1013", "t1055", "t1053", "t1058", "t1166", "t1178", "t1165", "t1169", "t1206", "t1078", "t1100", "t1134", "t1009", "t1197", "t1088", "t1146", "t1191", "t1116", "t1223", "t1109", "t1122", "t1196", "t1207", "t1140", "t1089", "t1038", "t1073", "t1211", "t1181", "t1107", "t1222", "t1006", "t1144", "t1158", "t1147", "t1143", "t1148", "t1183", "t1054", "t1066", "t1070", "t1202", "t1130", "t1118", "t1152", "t1149", "t1036", "t1112", "t1170", "t1126", "t1096", "t1027", "t1150", "t1205", "t1186", "t1093", "t1055", "t1108", "t1121", "t1117", "t1014", "t1085", "t1064", "t1218", "t1216", "t1198", "t1045", "t1151", "t1221", "t1099", "t1127", "t1078", "t1102", "t1220", "t1098", "t1139", "t1110", "t1003", "t1081", "t1214", "t1212", "t1187", "t1179", "t1056", "t1141", "t1208", "t1142", "t1171", "t1040", "t1174", "t1145", "t1167", "t1111", "t1087", "t1010", "t1217", "t1083", "t1046", "t1135", "t1040", "t1201", "t1120", "t1069", "t1057", "t1012", "t1018", "t1063", "t1082", "t1016", "t1049", "t1033", "t1124", "t1155", "t1017", "t1175", "t1210", "t1037", "t1097", "t1076", "t1105", "t1021", "t1091", "t1051", "t1184", "t1080", "t1072", "t1077", "t1028", "t1123", "t1119", "t1115", "t1213", "t1005", "t1039", "t1025", "t1074", "t1114", "t1056", "t1185", "t1113", "t1125", "t1020", "t1002", "t1022", "t1030", "t1048", "t1041", "t1011", "t1052", "t1029", "t1043", "t1092", "t1090", "t1094", "t1024", "t1132", "t1001", "t1172", "t1008", "t1188", "t1104", "t1026", "t1079", "t1205", "t1219", "t1105", "t1071", "t1032", "t1095", "t1065", "t1102"]
    MITRE_TECHNIQUE_NAMES = ["process_injection", "signed_binary_proxy_execution", "process_injection"] # incomplete list
    MITRE_TACTICS = ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration", "command_and_control"]
    MITRE_GROUPS =  ["g0018", "g0006", "g0005", "g0023", "g0025", "g0026", "g0073", "g0007", "g0016", "g0022", "g0013", "g0050", "g0064", "g0067", "g0001", "g0063", "g0060", "g0008", "g0058", "g0003", "g0080", "g0052", "g0070", "g0012", "g0079", "g0009", "g0035", "g0074", "g0017", "g0031", "g0066", "g0020", "g0051", "g0053", "g0037", "g0046", "g0061", "g0047", "g0036", "g0078", "g0043", "g0072", "g0004", "g0032", "g0077", "g0065", "g0030", "g0059", "g0045", "g0002", "g0021", "g0069", "g0019", "g0055", "g0014", "g0049", "g0071", "g0040", "g0011", "g0068", "g0033", "g0056", "g0024", "g0075", "g0048", "g0034", "g0029", "g0054", "g0038", "g0041", "g0039", "g0062", "g0015", "g0028", "g0027", "g0076", "g0010", "g0044"]
    MITRE_SOFTWARE = ["s0066", "s0065", "s0202", "s0309", "s0045", "s0092", "s0319", "s0296", "s0304", "s0310", "s0292", "s0099", "s0073", "s0110", "s0129", "s0093", "s0031", "s0245", "s0128", "s0234", "s0239", "s0127", "s0017", "s0268", "s0190", "s0069", "s0089", "s0114", "s0293", "s0252", "s0204", "s0014", "s0043", "s0119", "s0025", "s0274", "s0077", "s0030", "s0261", "s0222", "s0160", "s0220", "s0323", "s0144", "s0107", "s0020", "s0023", "s0054", "s0106", "s0154", "s0244", "s0126", "s0212", "s0137", "s0050", "s0046", "s0115", "s0235", "s0187", "s0255", "s0243", "s0301", "s0021", "s0200", "s0213", "s0281", "s0134", "s0186", "s0300", "s0320", "s0105", "s0315", "s0038", "s0062", "s0024", "s0081", "s0064", "s0082", "s0091", "s0152", "s0076", "s0181", "s0171", "s0267", "s0120", "s0182", "s0143", "s0036", "s0173", "s0193", "s0277", "s0095", "s0168", "s0049", "s0032", "s0026", "s0249", "s0290", "s0237", "s0008", "s0132", "s0047", "s0151", "s0037", "s0214", "s0246", "s0224", "s0071", "s0061", "s0170", "s0087", "s0135", "s0009", "s0232", "s0040", "s0070", "s0068", "s0322", "s0321", "s0203", "s0101", "s0278", "s0259", "s0260", "s0231", "s0100", "s0189", "s0015", "s0163", "s0044", "s0201", "s0283", "s0325", "s0215", "s0088", "s0265", "s0276", "s0271", "s0288", "s0250", "s0162", "s0156", "s0236", "s0211", "s0042", "s0121", "s0010", "s0282", "s0317", "s0167", "s0303", "s0175", "s0002", "s0179", "s0133", "s0051", "s0280", "s0084", "s0083", "s0080", "s0079", "s0149", "s0284", "s0256", "s0233", "s0205", "s0228", "s0247", "s0102", "s0272", "s0210", "s0039", "s0056", "s0034", "s0108", "s0104", "s0033", "s0198", "s0118", "s0299", "s0286", "s0138", "s0285", "s0052", "s0264", "s0229", "s0165", "s0072", "s0016", "s0208", "s0122", "s0316", "s0289", "s0158", "s0048", "s0097", "s0124", "s0291", "s0254", "s0013", "s0067", "s0012", "s0216", "s0150", "s0177", "s0139", "s0145", "s0194", "s0223", "s0184", "s0113", "s0279", "s0238", "s0029", "s0078", "s0147", "s0196", "s0197", "s0192", "s0006", "s0269", "s0262", "s0055", "s0241", "s0169", "s0295", "s0172", "s0326", "s0153", "s0075", "s0019", "s0166", "s0125", "s0174", "s0258", "s0003", "s0112", "s0270", "s0240", "s0103", "s0090", "s0148", "s0313", "s0253", "s0085", "s0074", "s0111", "s0195", "s0053", "s0185", "s0140", "s0294", "s0028", "s0063", "s0217", "s0007", "s0327", "s0218", "s0226", "s0159", "s0273", "s0157", "s0035", "s0227", "s0324", "s0305", "s0225", "s0058", "s0188", "s0328", "s0142", "s0018", "s0242", "s0060", "s0096", "s0098", "s0011", "s0329", "s0057", "s0164", "s0146", "s0131", "s0004", "s0183", "s0266", "s0307", "s0306", "s0308", "s0094", "s0001", "s0178", "s0199", "s0302", "s0263", "s0116", "s0221", "s0130", "s0275", "s0022", "s0136", "s0207", "s0257", "s0180", "s0109", "s0206", "s0005", "s0155", "s0219", "s0191", "s0176", "s0059", "s0141", "s0041", "s0312", "s0314", "s0161", "s0298", "s0123", "s0297", "s0318", "s0117", "s0311", "s0248", "s0251", "s0287", "s0027", "s0230", "s0086"]
    MITRE_ALL = ["attack." + item for item in MITRE_TECHNIQUES + MITRE_TECHNIQUE_NAMES + MITRE_TACTICS + MITRE_GROUPS + MITRE_SOFTWARE]

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
            yaml_parts = yaml.load_all(f)
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

        self.assertEqual(files_with_incorrect_extensions, [],
                        "There are rule files with extensions other than .yml")


    def test_confirm_correct_mitre_tags(self):
        files_with_incorrect_mitre_tags = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            tags = self.get_rule_part(file_path=file, part_name="tags")
            if tags:
                for tag in tags:
                    if tag not in self.MITRE_ALL and tag.startswith("attack."):
                        print("Rule {} has the following incorrect tag {}".format(file, tag))
                        files_with_incorrect_mitre_tags.append(file)

        self.assertEqual(files_with_incorrect_mitre_tags, [],
                         "There are rules with incorrect MITRE Tags")


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
                    print("Rule {} has duplicate filters".format(file))
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

        self.assertEqual(files_with_duplicate_filters, [],
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

        self.assertEqual(faulty_detections, [],
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

        self.assertEqual(faulty_detections, [],
                         "There are rule files with exactly the same detection logic.")


    def test_source_eventlog(self):
        faulty_detections = []

        for file in self.yield_next_rule_file_path(self.path_to_rules):
            detection = self.get_rule_part(file_path = file, part_name = "detection")
            detection_str = str(detection).lower()
            if "'source': 'eventlog'" in detection_str:
                faulty_detections.append(file)

        self.assertEqual(faulty_detections, [],
                         "There are detections with 'Source: Eventlog'. This does not add value to the detection.")


    def test_event_id_instead_of_process_create(self):
        faulty_detections = []
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            with open(file) as f:
                for line in f:
                    if re.search(r'.*EventID: (?:1|4688).*', line) and file not in faulty_detections:
                        faulty_detections.append(file)

        # Tareq won't enable until all existing rules are migrated to prevent breaking all CI builds
        # self.assertEqual(faulty_detections, [],
        #                  "There are rules still using Sysmon 1 or Event ID 4688. Please migrate to the process_creation category.")

        # Report but do not throw an error
        if faulty_detections:
            print("The following rules still use Sysmon 1 or Event ID 4688.")
            print("Please migrate to the process_creation category.")
            print("List length is: {}".format(len(faulty_detections)))
            print("------------------------------------------------")
            print(*faulty_detections, sep='\n')


if __name__ == "__main__":
    unittest.main()
