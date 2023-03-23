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

def yield_next_rule_file_path(path_to_rules: str) -> str:
    for root, _, files in os.walk(path_to_rules):
        for file in files:
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

def get_logsource_dict(path_to_rules, broken_rules):
    """
        Return a list of dicts of all unique log sources
    """
    logsource_dict_list_tmp = []

    # Add as many specific service log sources we have defined
    security_service_eids = []
    powershell_service_eids = []

    for file in yield_next_rule_file_path(path_to_rules):
        if file not in broken_rules:
            logsource = get_rule_part(file_path=file, part_name="logsource")
            detection = get_rule_part(file_path=file, part_name="detection")
            logsource.pop("definition", None)

            if (("product" in logsource.keys()) and (len(logsource) == 1)):
                # We skip rules that do not specify exact services for V0.1
                continue
            else:
                if "product" in logsource:
                    # For V0.1 we check for windows logs only
                    if logsource["product"].lower() == "windows":
                            
                            # We order the logsource dict to avoid duplicates
                            ordered_dict = dict(collections.OrderedDict(sorted(logsource.items())))
                            if  ordered_dict not in logsource_dict_list_tmp:
                                logsource_dict_list_tmp.append(ordered_dict)

                    if "category" in logsource:
                        pass
                    elif "service" in logsource:

                        if logsource["service"].lower() == "security":
                            eid_list = extract_events_ids(detection)
                            for eid in eid_list:
                                if eid not in security_service_eids:
                                    security_service_eids.append(eid)

                        elif logsource["service"].lower() == "powershell":
                            eid_list = extract_events_ids(detection)
                            for eid in eid_list:
                                if eid not in powershell_service_eids:
                                    powershell_service_eids.append(eid)
        
    logsource_dict_list = []
    for i in logsource_dict_list_tmp:
        i['EventIDs'] = []
        if 'service' in i:
            if i['service'].lower() == "security":
                i['EventIDs'] = security_service_eids
            elif i['service'].lower() == "powershell":
                i['EventIDs'] = powershell_service_eids
        logsource_dict_list.append(i)

    return logsource_dict_list

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
    parser = argparse.ArgumentParser(description='SIGMA Logsource Checker')
    parser.add_argument('-d', help='Path to input directory (SIGMA rules folder; recursive)', metavar='sigma-rules-folder', required=True)
    parser.add_argument('-f', help='XML output of the command "gpresult.exe /x [path]"', metavar='gpresult')
    #parser.add_argument('-v', help='Get audit and logging details for every rule', metavar='Verbose')
    #parser.add_argument('-vv', help='Get audit and logging details for every rule', metavar='Very Verbose')
    args = parser.parse_args()

    if os.path.isdir(args.d):
        path_to_rules = args.d
    else:
        print("The path provided isn't a directory: %s" % args.d)
        exit(1)

    if args.f:
        gpresult = args.f
        subcategory_id, enabled_other_logs = parse_gpresult(gpresult)
    else:
        subcategory_id = []
        enabled_other_logs = OTHER_EVENT_ID_MAPPING

    print("Discovering used log sources ...")
    
    faulty_rules = test_invalid_logsource_attributes(path_to_rules)
    logsource_dict_list = get_logsource_dict(path_to_rules, faulty_rules)

    print(logsource_dict_list)

    print("Checking audit/logging policies ...")

    for logsource in logsource_dict_list:
        if logsource['EventIDs']:
            if logsource['service'] == "security":
                for event in logsource['EventIDs']:
                    for key, value in SECURITY_EVENT_ID_MAPPING.items():
                        if value['EventIDs']:
                            if ((event in value['EventIDs']) and (key not in subcategory_id)):
                                print("  -> Audit policy '{}' must be enabled".format(value['Name']))
                                subcategory_id.append(key)
            elif logsource['service'] == "powershell":
                pwsh5 = "Windows Components/Windows PowerShell"
                #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks
                for key, value in enabled_other_logs.items():
                    for element in value:
                        for key_, value_ in element.items():
                            if key_ == pwsh5:
                                if value_ != "Enabled":
                                    print("  -> PowerShell policy '{}' must be enabled".format(key_))
        else:
            if "service" in logsource:
                if logsource['service'].lower() == "powershell":
                    pwsh5 = "Windows Components/Windows PowerShell"
                    #pwsh7 = "PowerShell Core" # TODO: Add PWSH7 Checks
                    
                    for key, value in enabled_other_logs.items():
                        if key == pwsh5:
                            for element in value:
                                for key_, value_ in element.items():
                                    if value_ != "Enabled":
                                        print("  -> PowerShell policy '{}' must be enabled".format(key_))
            elif "category" in logsource:
                if logsource['category'].lower() == 'process_creation':
                    pass # TODO: Add checks in future version

    