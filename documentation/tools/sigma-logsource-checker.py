# Author: Nasreddine Bencherchali (@nas_bench) / Nextron Systems

__version__ = "0.1.0"

from time import sleep
import yaml
import os
import argparse
from colorama import init
from colorama import Fore
import collections
import xml.etree.ElementTree as ET
from collections import defaultdict

SECURITY_EVENT_ID_MAPPING = {
    # Account Logon
    "{0CCE923F-69AE-11D9-BED3-505054503030}": {"EventIDs": [4774, 4775, 4776, 4777], "Name": "Audit Credential Validation"},
    "{0CCE9242-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4768, 4771, 4772], "Name": "Audit Kerberos Authentication Service"},
    "{0CCE9240-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4769, 4770, 4773], "Name": "Audit Kerberos Service Ticket Operations"},
    "{0CCE9241-69AE-11D9-BED3-505054503030}" : { "EventIDs": [], "Name": "Audit Other Account Logon Events"},
    # Account Management
    "{0CCE9239-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4783, 4784, 4785, 4786, 4787, 4788, 4789, 4790, 4791, 4792], "Name": "Audit Application Group Management"},
    "{0CCE9236-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4741, 4742, 4743], "Name": "Audit Computer Account Management"},
    "{0CCE9238-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4749, 4750, 4751, 4752, 4753], "Name": "Audit Distribution Group Management"},
    "{0CCE923A-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4782, 4793], "Name": "Audit Other Account Management Events"},
    "{0CCE9237-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4731, 4732, 4733, 4734, 4735, 4764, 4799, 4727, 4737, 4728, 4729, 4730, 4754, 4755, 4756, 4757, 4758], "Name": "Audit Security Group Management"},
    "{0CCE9235-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798, 5376, 5377], "Name": "Audit User Account Management"},
    # Detailed Tracking
    "{0CCE922D-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4692, 4693, 4694, 4695], "Name": "Audit DPAPI Activity"},
    "{0CCE9248-69AE-11D9-BED3-505054503030}" : { "EventIDs": [6416, 6419, 6420, 6421, 6422, 6423, 6424], "Name": "Audit PNP Activity"},
    "{0CCE922B-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4688, 4696], "Name": "Audit Process Creation"},
    "{0CCE922C-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4689], "Name": "Audit Process Termination"},
    "{0CCE922E-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5712], "Name": "Audit RPC Events"},
    "{0CCE924A-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4703], "Name": "Audit Token Right Adjusted"},
    # DS Access
    "{0CCE923E-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4928, 4929, 4930, 4931, 4934, 4935, 4936, 4937], "Name": "Audit Detailed Directory Service Replication"},
    "{0CCE923B-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4661, 4662], "Name": "Audit Directory Service Access"},
    "{0CCE923C-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5136, 5137, 5138, 5139, 5141], "Name": "Audit Directory Service Changes"},
    "{0CCE923D-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4932, 4933], "Name": "Audit Directory Service Replication"},
    # Logon/Logoff
    "{0CCE9217-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4625], "Name": "Audit Account Lockout"},
    "{0CCE9247-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4626], "Name": "Audit User/Device Claims"},
    "{0CCE9249-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4627], "Name": "Audit Group Membership"},
    "{0CCE921A-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4978, 4979, 4980, 4981, 4982, 4983, 4984], "Name": "Audit IPsec Extended Mode"},
    "{0CCE9218-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4646, 4650, 4651, 4652, 4653, 4655, 4976, 5049, 5453], "Name": "Audit IPsec Main Mode"},
    "{0CCE9219-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4977, 5451, 5452], "Name": "Audit IPsec Quick Mode"},
    "{0CCE9216-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4634, 4647], "Name": "Audit Logoff"},
    "{0CCE9215-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4624, 4625, 4648, 4675], "Name": "Audit Logon"},
    "{0CCE9243-69AE-11D9-BED3-505054503030}" : { "EventIDs": [6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280], "Name": "Audit Network Policy Server"},
    "{0CCE921C-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633], "Name": "Audit Other Logon/Logoff Events"},
    "{0CCE921B-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4964, 4672], "Name": "Audit Special Logon"},
    # Object Access
    "{0CCE9222-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4665, 4666, 4667, 4668], "Name": "Audit Application Generated"},
    "{0CCE9221-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4868, 4869, 4870, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4886, 4887, 4888, 4889, 4890, 4891, 4892, 4893, 4894, 4895, 4896, 4897, 4898], "Name": "Audit Certification Services"},
    "{0CCE9244-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5145], "Name": "Audit Detailed File Share"},
    "{0CCE9224-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5140, 5142, 5143, 5144, 5168], "Name": "Audit File Share"},
    "{0CCE921D-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4656, 4658, 4660, 4663, 4664, 4670, 4985, 5051], "Name": "Audit File System"},
    "{0CCE9226-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5031, 5150, 5151, 5154, 5155, 5156, 5157, 5158, 5159], "Name": "Audit Filtering Platform Connection"},
    "{0CCE9225-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5152, 5153], "Name": "Audit Filtering Platform Packet Drop"},
    "{0CCE9223-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4658, 4690], "Name": "Audit Handle Manipulation"},
    "{0CCE921F-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4656, 4658, 4660, 4663], "Name": "Audit Kernel Object"},
    "{0CCE9227-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4671, 4691, 4698, 4699, 4700, 4701, 4702, 5148 ,5149, 5888, 5889, 5890], "Name": "Audit Other Object Access Events"},
    "{0CCE921E-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4656, 4657, 4658, 4660, 4663, 4670, 5039], "Name": "Audit Registry"},
    "{0CCE9245-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4656, 4658, 4663], "Name": "Audit Removable Storage"},
    "{0CCE9220-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4661], "Name": "Audit SAM"},
    "{0CCE9246-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4818], "Name": "Audit Central Access Policy Staging"},
    # Policy Change
    "{0CCE922F-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4715, 4719, 4817, 4902, 4906, 4907, 4908, 4912, 4904, 4905], "Name": "Audit Audit Policy Change"},
    "{0CCE9230-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4670, 4706, 4707, 4716, 4713, 4717, 4718, 4739, 4864, 4865, 4866, 4867], "Name": "Audit Authentication Policy Change"},
    "{0CCE9231-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4703, 4704, 4705, 4670, 4911, 4913], "Name": "Audit Authorization Policy Change"},
    "{0CCE9233-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4709, 4710, 4711, 4712, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047, 5048, 5440, 5441, 5442, 5443, 5444, 5446, 5448, 5449, 5450, 5456, 5457, 5458, 5459, 5460, 5461, 5462, 5463, 5464, 5465, 5466, 5467, 5468, 5471, 5472, 5473, 5474, 5477], "Name": "Audit Filtering Platform Policy Change"},
    "{0CCE9232-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4956, 4957, 4958], "Name": "Audit MPSSVC Rule-Level Policy Change"},
    "{0CCE9234-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4714, 4819, 4826, 4909, 4910, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5447, 6144, 6145], "Name": "Audit Other Policy Change Events"},
    # Privilege Use
    "{0CCE9229-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4673, 4674, 4985], "Name": "Audit Non Sensitive Privilege Use"},
    "{0CCE922A-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4985], "Name": "Audit Other Privilege Use Events"},
    "{0CCE9228-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4673, 4674, 4985], "Name": "Audit Sensitive Privilege Use"},
    # System
    "{0CCE9213-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4960, 4961, 4962, 4963, 4965, 5478, 5479, 5480, 5483, 5484, 5485], "Name": "Audit IPsec Driver"},
    "{0CCE9214-69AE-11D9-BED3-505054503030}" : { "EventIDs": [5024, 5025, 5027, 5028, 5029, 5030, 5032, 5033, 5034, 5035, 5037, 5058, 5059, 6400, 6401, 6402, 6403, 6404, 6405, 6406, 6407, 6408, 6409], "Name": "Audit Other System Events"},
    "{0CCE9210-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4608, 4616, 4621], "Name": "Audit Security State Change"},
    "{0CCE9211-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4610, 4611, 4614, 4622, 4697], "Name": "Audit Security System Extension"},
    "{0CCE9212-69AE-11D9-BED3-505054503030}" : { "EventIDs": [4612, 4615, 4618, 4816, 5038, 5056, 5062, 5057, 5060, 5061, 6281, 6410], "Name": "Audit System Integrity"}
}

OTHER_EVENT_ID_MAPPING = {
    'PowerShell Core': [
        {'Turn on Module Logging': 'Disabled'},
        {'Turn on PowerShell Script Block Logging': 'Disabled'},
        {'Turn on PowerShell Transcription': 'Disabled'}
        ], 
    'System/Audit Process Creation': [
        {'Include command line in process creation events': 'Disabled'}
        ], 
    'Windows Components/Windows PowerShell': [
        {'Turn on Module Logging': 'Disabled'},
        {'Turn on PowerShell Script Block Logging': 'Disabled'},
        {'Turn on PowerShell Transcription': 'Disabled'}]
}

WINDOWS_SYSMON_PROCESS_CREATION_FIELDS = ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser"]

# A reduced set of unique fields that only available to Sysmon/1 - Used for testing
WINDOWS_SYSMON_SPECIAL_PROCESS_CREATION_FIELDS = ["RuleName", "UtcTime", "ProcessGuid", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentCommandLine", "ParentUser"]

WINDOWS_SECURITY_PROCESS_CREATION_FIELDS = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName", "MandatoryLabel"]

# A reduced set of unique fields that only available to Security/4688 - Used for testing
WINDOWS_SECURITY_SPECIAL_PROCESS_CREATION_FIELDS = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName", "MandatoryLabel"]

def yield_next_rule_file_path(path_to_rules: str) -> str:
    for root, _, files in os.walk(path_to_rules):
        for file in files:
            if file.endswith(".yml"):
                yield os.path.join(root, file)

def get_rule_part(file_path: str, part_name: str):
    yaml_dicts = get_rule_yaml(file_path)
    for yaml_part in yaml_dicts:
        if part_name in yaml_part.keys():
            return yaml_part[part_name]

    return None

def get_rule_yaml(file_path: str) -> dict:
    data = []

    with open(file_path, encoding='utf-8') as f:
        yaml_parts = yaml.safe_load_all(f)
        for part in yaml_parts:
            data.append(part)

    return data

def extract_events_ids(detection):
    eids_list = []
    for key, value in detection.items():
        if type(value) == dict:
            for key_, value_ in value.items():
                if key_ == "EventID":
                    if type(value_) == int:
                        eids_list.append(value_)
                    elif type(value_) == list:
                        for i in value_:
                            eids_list.append(i)
        else:
            pass
    
    return eids_list
    

def test_invalid_logsource_attributes(path_to_rules):
    """
        Returns list of rules that leverage unknown logsource
    """
    faulty_rules = []
    valid_logsource = [
        'category',
        'product',
        'service',
        'definition',
    ]

    for file in yield_next_rule_file_path(path_to_rules):
        logsource = get_rule_part(file_path=file, part_name="logsource")
        if not logsource:
            print("Rule {} has no 'logsource'.".format(file))
            faulty_rules.append(file)
            continue
        valid = True
        for key in logsource:
            if key.lower() not in valid_logsource:
                print("Rule {} has a logsource with an invalid field ({})".format(file, key))
                valid = False
            elif not isinstance(logsource[key], str):
                print("Rule {} has a logsource with an invalid field type ({})".format(file, key))
                valid = False
        if not valid:
            faulty_rules.append(file)

    return faulty_rules

def extract_fields(detection):

    list_of_fields = []

    for key, value in detection.items():
        if type(value) == list:
            for element in value:
                if type(element) == dict:
                    for key_, value_ in element.items():
                        field = key_.split("|")[0]
                        if field not in list_of_fields:
                            list_of_fields.append(field)
        if type(value) == dict:
            for key_, value_ in value.items():
                field = key_.split("|")[0]
                if field not in list_of_fields:
                        list_of_fields.append(field)
    return list_of_fields

def get_logsource_dict(path_to_rules, broken_rules):
    """
        Return a list of dicts of all unique log sources
    """
    logsource_dict_list_tmp = []

    # Add as many specific service log sources we have defined
    windows_service_security_dict = defaultdict(list)
    windows_service_powershell_dict = defaultdict(list)
    windows_category_process_creation_dict = defaultdict(list)
    windows_category_ps_module_dict = defaultdict(list)
    windows_category_ps_script_dict = defaultdict(list)

    for file_ in yield_next_rule_file_path(path_to_rules):
        if file_ not in broken_rules:
            logsource = get_rule_part(file_path=file_, part_name="logsource")
            detection = get_rule_part(file_path=file_, part_name="detection")
            logsource.pop("definition", None)

            if (("product" in logsource.keys()) and (len(logsource) == 1)):
                # We skip rules that do not specify exact services for V0.1 // Mainly the generic MIMIKATZ rule
                continue
            else:
                if "product" in logsource:
                    # For V0.1 we check for windows logs only
                    if logsource["product"].lower() == "windows":

                        if "category" in logsource:
                            if logsource['category'] == "process_creation":
                                # {"rule_file_name" : [fields used]}
                                fields = extract_fields(detection)
                                windows_category_process_creation_dict[file_] = fields

                            elif logsource['category'] == "ps_script":
                                fields = extract_fields(detection)
                                windows_category_ps_script_dict[file_] = fields

                            elif logsource['category'] == "ps_module":
                                # {"rule_file_name" : [fields used]}
                                fields = extract_fields(detection)
                                windows_category_ps_module_dict[file_] = fields
                                
                        elif "service" in logsource:
                            if logsource["service"].lower() == "security":
                                eid_list = extract_events_ids(detection)
                                windows_service_security_dict[file_] = eid_list
                                

                            elif logsource["service"].lower() == "powershell":
                                eid_list = extract_events_ids(detection)
                                windows_service_powershell_dict[file_] = eid_list

    return windows_service_security_dict, windows_service_powershell_dict, windows_category_process_creation_dict, windows_category_ps_module_dict, windows_category_ps_script_dict

def enrich_logsource_dict(logsource_dict_list):
    for logsource in logsource_dict_list:
        if "product" in logsource.keys:
            if logsource["product"] == "windows":
                if "service" in logsource.keys:
                    pass
                elif "category" in logsource.keys:
                    pass

def parse_gpresult(gpresult):
    """
        Parses GPResult command XML output
    """
    enabled_sec_policies = []
    enabled_other_logs = defaultdict(list)
    
    tree = ET.parse(gpresult)
    root = tree.getroot()
    for child in root:
        if "ComputerResults" in child.tag:
            computerResultsNode = child
            break
    extensionDataList = []
    for i in computerResultsNode:
        if "ExtensionData" in i.tag:
            extensionDataList.append(i)
        
    for i in extensionDataList:
        ext_type = i[0].attrib[next(iter(i[0].attrib))]
        if "AuditSettings" in ext_type:
            auditSettings = i[0]
            for audit in auditSettings:
                SubcategoryGuid = ""
                SettingValue = ""
                for element in audit:
                    if "SubcategoryGuid" in element.tag:
                        SubcategoryGuid = element
                    elif "SettingValue" in element.tag:
                        SettingValue = element
                # If the audit settings is enabled for "Success" or both "Success and Failure". Then it's okay (for V0.1)
                if SettingValue.text == "1" or SettingValue.text == "3":
                    enabled_sec_policies.append(SubcategoryGuid.text.upper())
        elif "Registry" in ext_type:
            registrySettings = i[0]
            for policy in registrySettings:
                if "}Policy" in policy.tag:
                    policyName = ""
                    policyState = ""
                    policyCategory = ""
                    for element in policy:
                        if "Name" in element.tag:
                            policyName = element
                        elif "State" in element.tag:
                            policyState = element
                        elif "Category" in element.tag:
                            policyCategory = element
                    # {"Category": {"Name": "State"}}
                    tmp = {policyName.text : policyState.text}
                    enabled_other_logs[policyCategory.text].append(tmp)
    
    return enabled_sec_policies, enabled_other_logs
    



if __name__ == "__main__":

    print(f"""
       _____ _                                                                                   
      / ___/(_)___ _____ ___  ____ _                                                             
      \__ \/ / __ `/ __ `__ \/ __ `/                                                             
     ___/ / / /_/ / / / / / / /_/ /                                                              
    /____/_/\__, /_/ /_/ /_/\__,_/                           ________              __            
       / / /____/  ____ __________  __  _______________     / ____/ /_  ___  _____/ /_____  _____
      / /   / __ \/ __ `/ ___/ __ \/ / / / ___/ ___/ _ \   / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/
     / /___/ /_/ / /_/ (__  ) /_/ / /_/ / /  / /__/  __/  / /___/ / / /  __/ /__/ ,< /  __/ /    
    /_____/\____/\__, /____/\____/\__,_/_/   \___/\___/   \____/_/ /_/\___/\___/_/|_|\___/_/     
                /____/  by Nasreddine Bencherchali (Nextron Systems), v{__version__}             
    """)
    
    parser = argparse.ArgumentParser(description='SIGMA Logsource Checker')
    parser.add_argument('-d', help='Path to input directory (SIGMA rules folder; recursive)', metavar='sigma-rules-folder', required=True)
    parser.add_argument('-gp', help='XML output of the command "gpresult.exe /x [path]"', metavar='gpresult')
    #parser.add_argument('-sysmon', help='Sysmon configuration', metavar='sysmon-config') # TODO: add Sysmon config parser
    parser.add_argument('-v', help='Get audit and logging details for every rule', action="store_true")
    #parser.add_argument('-vv', help='Get audit and logging details for every rule', metavar='Very Verbose')
    args = parser.parse_args()

    if os.path.isdir(args.d):
        path_to_rules = args.d
    else:
        print("The path provided isn't a directory: %s" % args.d)
        exit(1)

    if args.gp:
        gpresult = args.gp
        print("Parsing gpresults file (XML) %s ...\n" % args.gp)
        subcategory_id, enabled_other_logs = parse_gpresult(gpresult)
    else:
        subcategory_id = []
        enabled_other_logs = OTHER_EVENT_ID_MAPPING

    print("Discovering used log sources ...\n")
    
    faulty_rules = test_invalid_logsource_attributes(path_to_rules)
    windows_service_security_dict, windows_service_powershell_dict, windows_category_process_creation_dict, windows_category_ps_module_dict, windows_category_ps_script_dict = get_logsource_dict(path_to_rules, faulty_rules)

    if args.v:

        print("Generating detailed logging requirements information for every rule...\n")
        sleep(1)

        if windows_category_process_creation_dict:
            print(f"\nChecking rules with logsource - 'product: windows / category: process_creation'...")
            # We check special fields. If they exist then we suggest the policy to be enabled
            for filename, fields in windows_category_process_creation_dict.items():
                special_fields_sysmon = []
                special_fields_security = []
                for field in fields:
                    if field in WINDOWS_SYSMON_SPECIAL_PROCESS_CREATION_FIELDS:
                        special_fields_sysmon.append(field)
                    elif field in WINDOWS_SECURITY_SPECIAL_PROCESS_CREATION_FIELDS:
                        special_fields_security.append(field)
                
                if special_fields_sysmon:
                    print("-> Rule '{}' uses fields: {} which Requires Microsoft-Windows-Sysmon EID 1 to be enabled".format(os.path.basename(filename), special_fields_sysmon))
                elif special_fields_security:
                    if "{0CCE922B-69AE-11D9-BED3-505054503030}" not in subcategory_id:
                        print("-> Rule '{}' uses fields: {} which Requires Microsoft Windows Security Auditing EID 4688 to be enabled".format(os.path.basename(filename), special_fields_security))
                else:
                    if "{0CCE922B-69AE-11D9-BED3-505054503030}" not in subcategory_id:
                        print("-> Rule '{}' uses fields: {} which Requires 'Microsoft Windows Security Auditing EID 4688' or 'Microsoft-Windows-Sysmon EID 1' to be enabled".format(os.path.basename(filename), fields))

        if windows_category_ps_module_dict:
            print(f"\nChecking rules with logsource - 'product: windows / category: ps_module'...")
            pwsh5_ps_module_enabled = False
            pwsh5 = "Windows Components/Windows PowerShell"
            #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks
            if pwsh5 in enabled_other_logs:
                if enabled_other_logs[pwsh5][0]['Turn on Module Logging'] == "Enabled":
                    pwsh5_ps_module_enabled = True

            for filename, fields in windows_category_ps_module_dict.items():
                if not pwsh5_ps_module_enabled:
                    print("-> Rule '{}' uses fields: {} which Requires Microsoft-Windows-PowerShell EID 4103 to be enabled".format(os.path.basename(filename), fields))
        
        if windows_category_ps_script_dict:
            print(f"\nChecking rules with logsource - 'product: windows / category: ps_script'...")
            pwsh5_ps_script_enabled = False
            pwsh5 = "Windows Components/Windows PowerShell"
            #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks
            if pwsh5 in enabled_other_logs:
                if enabled_other_logs[pwsh5][1]['Turn on PowerShell Script Block Logging'] == "Enabled":
                    pwsh5_ps_script_enabled = True
            for filename, fields in windows_category_ps_script_dict.items():
                if not pwsh5_ps_script_enabled:
                    print("-> Rule '{}' uses fields: {} which Requires Microsoft-Windows-PowerShell EID 4104 to be enabled".format(os.path.basename(filename), fields))

        if windows_service_security_dict:
            print(f"\nChecking rules using logsource - 'product: windows / service: security'...")
            for filename, eids in windows_service_security_dict.items():
                specific_eids = set()
                specific_subcategory = set()
                for eid in eids:
                    for key, value in SECURITY_EVENT_ID_MAPPING.items():
                        if value['EventIDs']:
                            if ((eid in value['EventIDs']) and (key not in subcategory_id)):
                                specific_eids.add(eid)
                                specific_subcategory.add((key, value['Name']))
                
                specific_eids = list(specific_eids)
                specific_subcategory = list(specific_subcategory)
                
                
                if len(specific_subcategory) > 1:
                    print("-> Rule '{}' uses EventIDs: {} which Requires:".format(os.path.basename(filename), specific_eids))
                    for i in specific_subcategory:
                        print("      - '{}' / {} to be enabled".format(i[1], i[0]))
                else:
                    if len(specific_subcategory) != 0:
                        print("-> Rule '{}' uses EventIDs: {} which Requires: '{}' / {} to be enabled".format(os.path.basename(filename), specific_eids, specific_subcategory[0][1], specific_subcategory[0][0]))


            
    else:

        print("Generating generic logging requirements information for the rule set...")
        sleep(1)

        # If no verbose mode was triggered we generate a generic audit policy suggestion for all rules
        # Process Creation Rules
        if windows_category_process_creation_dict:
            enable_sysmon = False
            enable_4688 = False
            print(f"\nChecking rules with logsource - 'product: windows / category: process_creation'...")
            # We check special fields. If they exist then we suggest the policy to be enabled
            all_process_creation_fields = []
            for filename, fields in windows_category_process_creation_dict.items():
                all_process_creation_fields += fields
            all_process_creation_fields = list(set(all_process_creation_fields))
            for field in WINDOWS_SYSMON_SPECIAL_PROCESS_CREATION_FIELDS:
                if field in all_process_creation_fields:
                    enable_sysmon = True
                    print("-> Rules use Sysmon EID 1 only fields. A Sysmon configuration monitoring Process Creation is required")
                    break
            if not enable_sysmon:
                for field in WINDOWS_SECURITY_SPECIAL_PROCESS_CREATION_FIELDS:
                    if field in all_process_creation_fields:
                        if "{0CCE922B-69AE-11D9-BED3-505054503030}" not in subcategory_id:
                            enable_4688 = True
                            print("-> Rules use Microsoft-Windows-Security-Auditing EID 4688 only fields. Audit policy sub-category {0CCE922B-69AE-11D9-BED3-505054503030} / 'Process Creation' must be enabled")
                            break
                        else:
                            print("Audit policy sub-category {0CCE922B-69AE-11D9-BED3-505054503030} / 'Process Creation' is already enabled")
                            break
                if not enable_4688:
                    print("-> Audit policy sub-category {0CCE922B-69AE-11D9-BED3-505054503030} / 'Process Creation' must be enabled")

        if windows_category_ps_module_dict:
            print(f"\nChecking rules with logsource - 'product: windows / category: ps_module'...")
            
            pwsh5 = "Windows Components/Windows PowerShell"
            #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks

            if pwsh5 in enabled_other_logs:
                if enabled_other_logs[pwsh5][0]['Turn on Module Logging'] != "Enabled":
                    print("-> Rules use Microsoft-Windows-PowerShell EID 4103. Audit policy 'Module Logging' must be enabled")
                else:
                    print("-> PowerShell 'Module Logging' is Enabled")
        
        if windows_category_ps_script_dict:
            print(f"\nChecking rules with logsource - 'product: windows / category: ps_script'...")
            
            pwsh5 = "Windows Components/Windows PowerShell"
            #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks

            if pwsh5 in enabled_other_logs:
                if enabled_other_logs[pwsh5][1]['Turn on PowerShell Script Block Logging'] != "Enabled":
                    print("-> Rules use Microsoft-Windows-PowerShell EID 4104. Audit policy PowerShell 'Script Block Logging' must be enabled")
                else:
                    print("-> PowerShell 'Script Block Logging' is Enabled")
        
        if windows_service_security_dict:
            print(f"\nChecking rules using logsource - 'product: windows / service: security'...")
            all_security_eids = []
            for filename, eids in windows_service_security_dict.items():
                all_security_eids += eids
            all_security_eids = list(set(all_security_eids))
            for eid in all_security_eids:
                for key, value in SECURITY_EVENT_ID_MAPPING.items():
                    if value['EventIDs']:
                        if ((eid in value['EventIDs']) and (key not in subcategory_id)):
                            print("-> Rules use events generated from audit policy sub-category '{}'. The audit policy '{}' must be enabled".format(key, value['Name']))
                            subcategory_id.append(key)
        
    print("\nFor more information on how to setup logging, you can visit: https://github.com/SigmaHQ/sigma/tree/master/rules-documentation/logsource-guides") 
