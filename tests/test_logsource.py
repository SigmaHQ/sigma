#!/usr/bin/env python3
"""
Checks for logsource or fieldname errors on all rules

WIP version

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
import collections


class TestRules(unittest.TestCase):

    path_to_rules = "rules"
    
    windows_category={
        "process_creation": ["CommandLine","Company","CurrentDirectory","Description","FileVersion","Hashes","Image","IntegrityLevel","LogonGuid","LogonId","OriginalFileName","ParentCommandLine","ParentImage","ParentProcessGuid","ParentProcessId","ParentUser","ProcessGuid","ProcessId","Product","TerminalSessionId","User"],
        "file_change": ["CreationUtcTime","Image","PreviousCreationUtcTime","ProcessGuid","ProcessId","TargetFilename","User"],
        "network_connection": ["DestinationHostname","DestinationIp","DestinationIsIpv6","DestinationPort","DestinationPortName","Image","Initiated","ProcessGuid","ProcessId","Protocol","SourceHostname","SourceIp","SourceIsIpv6","SourcePort","SourcePortName","User"],
        "sysmon_status": ["Configuration","ConfigurationFileHash","SchemaVersion","State","Version"],
        "process_termination":["Image","ProcessGuid","ProcessId","User"],
        "driver_load":["Hashes","ImageLoaded","Signature","SignatureStatus","Signed"],
        "image_load":["Company","Description","FileVersion","Hashes","Image","ImageLoaded","OriginalFileName","ProcessGuid","ProcessId","Product","Signature","SignatureStatus","Signed","User"],
        "create_remote_thread":["NewThreadId","SourceImage","SourceProcessGuid","SourceProcessId","SourceUser","StartAddress","StartFunction","StartModule","TargetImage","TargetProcessGuid","TargetProcessId","TargetUser"],
        "raw_access_thread":["Device","Image","ProcessGuid","ProcessId","User"],
        "process_access":["CallTrace","GrantedAccess","SourceImage","SourceProcessGUID","SourceProcessId","SourceThreadId","SourceUser","TargetImage","TargetProcessGUID","TargetProcessId","TargetUser"],
        "raw_access_read":["CreationUtcTime","Image","ProcessGuid","ProcessId","TargetFilename","User"],
        "file_event":["ProcessGuid","ProcessId","Image","TargetFilename","CreationUtcTime","User"],
        "registry_add":["EventType","ProcessGuid","ProcessId","Image","TargetObject","User"],
        "registry_delete":["Details","EventType","Image","ProcessGuid","ProcessId","TargetObject",],
        "registry_set":["Details","EventType","Image","ProcessGuid","ProcessId","TargetObject","User"],
        "registry_rename":["EventType","Image","NewName","ProcessGuid","ProcessId","TargetObject","User"],
        "registry_event":["Details","EventType","Image","NewName","ProcessGuid","ProcessId","TargetObject","User"],
        "create_stream_hash":["Contents","CreationUtcTime","Hash","Image","ProcessGuid","ProcessId","TargetFilename","User"],
        "pipe_created":["EventType","Image","PipeName","ProcessGuid","ProcessId","User"],
        "wmi_event":["Consumer","Destination","EventNamespace","EventType","Filter","Name","Operation","Query","Type","User"],
        "dns_query":["Image","ProcessGuid","ProcessId","QueryName","QueryResults","QueryStatus","User"],
        "file_delete":["Archived","Hashes","Image","IsExecutable","ProcessGuid","ProcessId","TargetFilename","User"],
        "clipboard_capture":["Archived","ClientInfo","Hashes","Image","ProcessGuid","ProcessId","Session","User"],
        "process_tampering":["Image","ProcessGuid","ProcessId","Type","User"],
        "file_block":["Hashes","Image","ProcessGuid","ProcessId","TargetFilename","User"], #SYSMONEVENT_FILE_BLOCK_SHREDDING add IsExecutable
        "ps_module":["ContextInfo","UserData","Payload"],
        "ps_script":["MessageNumber","MessageTotal","ScriptBlockText","ScriptBlockId","Path"],
    }
    
    # Calculate once use many times
    windows_category_keys = windows_category.keys()
    
    # Aurora FP
    windows_category["process_creation"] += ["GrandparentCommandLine"]
    windows_category["network_connection"] += ["CommandLine","ParentImage"]
    windows_category["create_remote_thread"] += ["User","SourceCommandLine","SourceParentProcessId","SourceParentImage","SourceParentCommandLine","TargetCommandLine","TargetParentProcessId","TargetParentImage","TargetParentCommandLine","IsInitialThread","RemoteCreation"]
    windows_category["file_delete"] += ["CommandLine","ParentImage","ParentCommandLine"]
    windows_category["file_event"] += ["CommandLine","ParentImage","ParentCommandLine","MagicHeader"]
    windows_category["image_load"] += ["CommandLine"]
    windows_category["process_access"] += ["SourceCommandLine","CallTraceExtended"]


    windows_commun = ["EventID","Provider_Name"]
    
    # Helper functions
    def yield_next_rule_file_path(self, path_to_rules: str) -> str:
        for root, _, files in os.walk(path_to_rules):
            for file in files:
                yield os.path.join(root, file)

    def get_rule_yaml(self, file_path: str) -> dict:
        data = []

        with open(file_path, encoding='utf-8') as f:
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

    def get_detection_field(self,detection: dict):
        data = []
        
        for search_identifier in detection:
            if isinstance(detection[search_identifier], dict):
                for field in detection[search_identifier]:
                    if "|" in field:
                        data.append(field.split('|')[0])
                    else:
                        data.append(field)
        return data        

    def fill_logsource(self,logsource: dict) -> dict:
        data = {"product":"","category":"","service":""}
        
        data["product"] = logsource["product"] if "product" in logsource.keys() else ""
        data["category"] = logsource["category"] if "category" in logsource.keys() else ""
        data["service"] = logsource["service"] if "service" in logsource.keys() else ""
        
        return data

    def add_hash(self):
        for key in self.windows_category_keys:
            if "Hashes" in self.windows_category[key]:
                self.windows_category[key].append("md5")
                self.windows_category[key].append("sha1")
                self.windows_category[key].append("sha256")
                self.windows_category[key].append("Imphash")

    #
    # test functions
    #
    def test_fieldname_case(self):
        files_with_fieldname_issues = []
        
        self.add_hash()
        
        for file in self.yield_next_rule_file_path(self.path_to_rules):
            logsource = self.get_rule_part(file_path=file, part_name="logsource")
            detection = self.get_rule_part(file_path=file, part_name="detection")
            
            if logsource and detection :
                full_logsource = self.fill_logsource(logsource)

                if full_logsource['product'] == "windows":
                    if full_logsource['category'] in self.windows_category_keys:
                        for field in self.get_detection_field(detection):
                            list_field = self.windows_category[full_logsource['category']] + self.windows_commun
                            
                            if not field in list_field:
                                print(
                                    Fore.RED + "Rule {} has the invalid field <{}>".format(file, field))
                                files_with_fieldname_issues.append(file)
                    
        self.assertEqual(files_with_fieldname_issues, [], Fore.RED +
                         "There are rule files which contains unkown field or with case error")        


if __name__ == "__main__":
    init(autoreset=True)
    # Run the tests
    unittest.main()