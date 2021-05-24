#!/usr/bin/python
# Copyright 2021 frack113

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Project: check_sigma_yml.py
Date: 24/05/2021
Author: frack
Version: 1.1
Description: This script check common error of Sigma SIEM rules.
Thanks: https://github.com/SigmaHQ/sigma/wiki/Specification
TODO:
 [x] manage action global rule
 [ ] manage action other rule
 [ ] Add more deep tests
 [ ] fix what is broken
 [ ] Cleanup
    
"""

import argparse
import itertools
import sys
import yaml
import pathlib
import csv
import re
import uuid
import requests

class info:
    filename    = ""
    etat        = ""
    title       = ""
    uuid        = ""
    related     = ""
    status      = ""
    description = ""
    date        = ""
    modified    = ""
    author      = ""
    references  = ""
    logsource   = ""
    detection   = ""
    fields      = ""
    falsepositives = ""
    level       = ""
    tags        = ""
    unknow      = ""

    def get_list(self):
     return [
        self.filename,
        self.etat,
        self.title,
        self.uuid,
        self.related,
        self.status,
        self.description,
        self.date,
        self.modified,
        self.author,
        self.references,
        self.logsource,
        self.detection,
        self.fields,
        self.falsepositives,
        self.level,
        self.tags,
        self.unknow ]
       
    def clean(self):
        self.filename    = ""
        self.etat        = ""
        self.title       = ""
        self.uuid        = ""
        self.related     = ""
        self.status      = ""
        self.description = ""
        self.date        = ""
        self.modified    = ""
        self.author      = ""
        self.references  = ""
        self.logsource   = ""
        self.detection   = ""
        self.fields      = ""
        self.falsepositives = ""
        self.level       = ""
        self.tags        = ""
        self.unknow      = ""   

# list of category,product or service
# Only for warning
# all find in rule no logic check
list_product  = ["antivirus","apache","cisco","django","firewall","linux","macos","netflow","python",
                "qualys","ruby_on_rails","sql","stormshield","spring","unix","windef","windows",
                "windows_defender","zeek"]

list_category = ["auditd","accounting","application","authentication","create_remote_thread","create_stream_hash","dns",
                "dns_query","driver_load","file_delete","file_event","firewall","image_load",
                "network_connection","other","pipe_created","process_access","process_creation",
                "proxy","raw_access_thread","registry_event","webserver","windows","wmi_event"]

list_service  = ["aaa","alarm","application","applocker","auditd","auth","clamav","cloudtrail","connection","dce_rpc",
                "dns","dns-server","driver-framework","guacamole","http","kerberos","modsecurity","Microsoft-ServiceBus-Client",
                "msexchange-management","ntlm","powershell","powershell-classic","rdp","security",
                "server","smb_files","sysmon","system","sshd","syslog","taskscheduler","vsftpd","windefend","wmi"]


# Thanks to sigmac 
def alliter(path):
    for sub in path.iterdir():
        if sub.name.startswith("."):
            continue
        if sub.is_dir():
            yield from alliter(sub)
        else:
            yield sub


def check_title(content):
    if "title" in content:
        if len(content["title"]) < 256:
            del content["title"]
            return "valid","Pass"
        else:
            del content["title"]
            return "error","Lenght of title is too long"            
    else:
        return "error","MISSING"

def check_id(content):
    if "id" in content:
        if uuid.UUID(content["id"]):
            del content["id"]
            return "valid","Pass"
        else:
            del content["id"]
            return "error","id is not a valid uuid"
    else:
        return "warning","Pass Optional"

def check_related (content):
    if "related" in content:
        del content["related"]
        return "valid","Pass"
    else:
        return "warning","Pass Optional"
    
def check_status  (content):
    if "status" in content:
        if content["status"] in ["stable","test","experimental"]:
            del content["status"]
            return "valid","Pass"
        else:
            del content["status"]
            return "error","Not a valid status"
    else:
        return "warning","Pass Optional"    

def check_description (content):
    if "description" in content:
        if len(content["description"]) < 65536:
            del content["description"]
            return "valid","Pass"
        else:
            del content["description"]
            return "warning","Lenght of title is too long"
    else:
        return "warning","Pass Optional"
    
def check_date (content):
    if "date" in content:
        if re.match('\d{4}/\d{1,2}/\d{1,2}',content["date"]):
            valid = True
        else:
            valid = False
        del content["date"]
        if valid:
            return "valid","Pass"
        else:
            return "error","Format invalid"
    else:
        return "warning","Pass Optional"

def check_modified (content):
    if "modified" in content:
        if re.match('\d{4}/\d{1,2}/\d{1,2}',content["modified"]):
            valid = True
        else:
            valid = False
        del content["modified"]
        if valid:
            return "valid","Pass"
        else:
            return "error","Format invalid"        
        del content["modified"]
    else:
        return "warning","Pass Optional"

def check_author (content):
    if "author" in content:
        del content["author"]
        return "valid","Pass"
    else:
        return "warning","Pass Optional"

def check_references (content):
    if "references" in content:
        if isinstance(content["references"],list):
            valid = True
            for url in content["references"]:
                try:
                    pass
                   # r = requests.get(url)
                   # if not r.status_code == 200:
                   #     valid = False
                except:
                    return "warning","One Ref is not a url"    
            del content["references"]
            if valid:
                return "valid","Pass"
            else:
                return "warning","Get not a 200 return code"
        else:
            del content["references"]
            return "error","Should be a list"            
    else:
        return "warning","Pass Optional"

def check_logsource (content):
    msg = ""
    if "logsource" in content:
        if "product" in content["logsource"]:
            if not content["logsource"]["product"] in list_product:
                msg = f'New product {content["logsource"]["product"]}'
        if "category" in content["logsource"]:
            if not content["logsource"]["category"] in list_category:
                msg = f'{msg} New category {content["logsource"]["category"]}'
        if "service" in content["logsource"]:
            if not content["logsource"]["service"] in list_service:
                msg = f'{msg} New service {content["logsource"]["service"]}'
        if msg == "":
            del content["logsource"]
            return "valid","Pass"
        else:
            del content["logsource"]
            return "valid",msg
    else:
        return "warning","Pass Optional"

def check_detection (content):
    if "detection" in content:
        del content["detection"]
        return "valid","Pass"
    else:
        return "error","Missing"

def check_fields (content):
    if "fields" in content:
        if isinstance(content["fields"],list):
            del content["fields"]
            return "valid","Pass"
        else:
            del content["fields"]
            return "error","Should be a list"
    else:
        return "warning","Pass Optional"

def check_falsepositives (content):
    if "falsepositives" in content:
        if isinstance(content["falsepositives"],list):
            del content["falsepositives"]
            return "valid","Pass"
        else:
            del content["falsepositives"]
            return "error","Should be a list"            
    else:
        return "warning","Pass Optional"

def check_level (content):
    if "level" in content:
        if content["level"] in ["informational","low","medium","high","critical"]:
            del content["level"]
            return "valid","Pass"
        else:
            del content["level"]
            return "error","Invalid level"
    else:
        return "warning","Pass Optional"   

def check_tags (content):
    if "tags" in content:
        if isinstance(content["tags"],list):
            valid = True
            for tag in content["tags"]:
                if ' ' in tag:
                    valid = False
            del content["tags"]
            if valid:
                return "valid","Pass"
            else:
                return "warnig","Format trouble"
        else:
            del content["tags"]
            return "error","Should be a list"            
    else:
        return "warning","Pass Optional"
    
def check_unknow(content):
    if len(content)>0:
        return "error", ','.join(content.keys())
    else:
        return "valid", ""
    
def clean_custom_field(content):
    custom=["enrichment","analysis","notes"]
    for field in custom:
        if field in content:
            del content[field]

def run_all_check(rule_dict,l_info):
    l_info.etat = "OK"
    
    #some field find in the rule as you can create your one
    clean_custom_field(rule_dict)
    
    r_level,l_info.title         = check_title(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.uuid          = check_id(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.related       = check_related(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.status        = check_status(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.description   = check_description(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.date          = check_date(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.modified      = check_modified(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.author        = check_author(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.references    = check_references(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.logsource     = check_logsource(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.detection     = check_detection(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.fields        = check_fields(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.falsepositives = check_falsepositives(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.level         = check_level(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.tags          = check_tags(rule_dict)
    if r_level == "error": l_info.etat = "NOK"
    r_level,l_info.unknow        = check_unknow(rule_dict)
    if r_level == "error": l_info.etat = "NOK"

        

'''
The main part
'''

argparser = argparse.ArgumentParser(description="Check the commun error in yml rule")
argparser.add_argument("--recurse", "-r", action="store_true", help="Use directory as input")
argparser.add_argument("--output", "-o", default="all_rule.csv", help="Output file name")
argparser.add_argument("inputs", nargs="*", help="the input")

cmdargs = argparser.parse_args()

if len(cmdargs.inputs) == 0:
    print("Nothing to do!")
    exit(0)

# Thanks to sigmac 
if cmdargs.recurse:
    list_yml = list(itertools.chain.from_iterable([list(alliter(pathlib.Path(p))) for p in cmdargs.inputs]))
else:
    list_yml = [pathlib.Path(p) for p in cmdargs.inputs]


csvfile = open (cmdargs.output,'w', newline='')
csvwriter = csv.writer(csvfile,delimiter=';')

header=["filename",
        "etat",
        "title",
        "id",
        "related",
        "status",
        "description",
        "date",
        "modified",
        "author",
        "references",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "unknow"]
csvwriter.writerow(header)

rule_data = info()
for yml_file in list_yml:
    rule_data.clean()
    merge = False
    rule_data.filename = yml_file.name
    with yml_file.open('rt',encoding='utf8') as f:
        data = yaml.safe_load_all(f)
        for rule in data:
            if "action" in rule:
                if rule["action"] == "global":
                    global_dict = rule
                    del global_dict["action"]
                    merge = True
                else:
                    print(f'{yml_file.name} warning this action is not implemented')
                    break
            else:
                if merge:
                    merge_rule = {**global_dict, **rule}  # Python 3.5
                    run_all_check(merge_rule,rule_data)
                    csvwriter.writerow(rule_data.get_list())
                else:
                    run_all_check(rule,rule_data)
                    csvwriter.writerow(rule_data.get_list())

csvfile.close()
