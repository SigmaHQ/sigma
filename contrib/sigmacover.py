# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: sigmacover.py
Date: 26/09/2021
Author: frack113
Version: 1.1
Description: 
    get cover of the rules vs backend
Requirements:
    python 3.7 min
    $ pip install ruyaml
Todo:
    - clean code and bug
    - better use of subprocess.run
    - have idea
"""


import re
import subprocess
import pathlib
import ruyaml
import json
import copy
import platform
import argparse

def get_sigmac(name,conf):
    infos = []
    if conf == None:
        options = ["python","../tools/sigmac","-t",name,"--debug","-rI","-o","dump.txt","../rules"]
    else:
        options = ["python","../tools/sigmac","-t",name,"-c",conf,"--debug","-rI","-o","dump.txt","../rules"]
    if platform.system() == "Windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        ret = subprocess.run(options,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             startupinfo=si
                             )
        my_regex = "Convertion Sigma input \S+\\\\(\w+\.yml) (\w+)"
    else:
        ret = subprocess.run(options,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             )
        my_regex = "Convertion Sigma input \S+/(\w+\.yml) (\w+)"   
    if not ret.returncode == 0:
        print (f"error {ret.returncode} in sigmac")
    log = pathlib.Path("sigmac.log")
    with log.open() as f:
        lines = f.readlines()
        for line in lines:
            if "Convertion Sigma input" in line:
                info = re.findall(my_regex,line)[0]
                infos.append(info)
    log.unlink()
    dump = pathlib.Path("dump.txt")
    if dump.exists():
        dump.unlink()
    return infos            

def update_dict(my_dict,my_data,backend):
    for file,state in my_data:
        my_dict[file][backend] = state

#the backend dict command line options
backend_dict = {
    "ala": None,
    "ala-rule": None,
    "arcsight": "../tools/config/elk-winlogbeat.yml",
    "arcsight-esm": "../tools/config/elk-winlogbeat.yml",
    "carbonblack": "../tools/config/elk-winlogbeat.yml",
    "chronicle": "../tools/config/elk-winlogbeat.yml",
    "crowdstrike": "../tools/config/elk-winlogbeat.yml",
    "csharp" : None,
    "devo": "../tools/config/elk-winlogbeat.yml",
    "ee-outliers": "../tools/config/winlogbeat-modules-enabled.yml",
    "elastalert": "../tools/config/winlogbeat-modules-enabled.yml",
    "elastalert-dsl": "../tools/config/winlogbeat-modules-enabled.yml",
    "es-dsl": "../tools/config/winlogbeat-modules-enabled.yml",
    "es-eql": "../tools/config/winlogbeat-modules-enabled.yml",
    "es-qs": "../tools/config/winlogbeat-modules-enabled.yml",
    "es-qs-lr": "../tools/config/logrhythm_winevent.yml",
    "es-rule": "../tools/config/winlogbeat-modules-enabled.yml",
    "es-rule-eql": "../tools/config/winlogbeat-modules-enabled.yml",
    "fireeye-helix": "../tools/config/elk-winlogbeat.yml",
    "graylog" : None,
    "grep" : None,
    "humio": "../tools/config/elk-winlogbeat.yml",
    "kibana": "../tools/config/winlogbeat-modules-enabled.yml",
    "kibana-ndjson": "../tools/config/winlogbeat-modules-enabled.yml",
    "lacework" : None,
    "limacharlie" : None,
    "logiq" : None,
    "logpoint" : None,
    "mdatp" : None,
    "netwitness" : None,
    "netwitness-epl" : None,
    "opensearch-monitor": "../tools/config/winlogbeat.yml",
    "powershell" : None,
    "qradar" : None,
    "qualys" : None,
    "sentinel-rule" : None,
    "splunk": "../tools/config/splunk-windows.yml",
    "splunkdm": "../tools/config/splunk-windows.yml",
    "splunkxml": "../tools/config/splunk-windows.yml",
    "sql": "../tools/config/elk-winlogbeat.yml",
    "sqlite": "../tools/config/elk-winlogbeat.yml",
    "stix": "../tools/config/stix2.0.yml",
    "sumologic" : None,
    "sumologic-cse" : None,
    "sumologic-cse-rule" : None,
    "sysmon": "../tools/config/elk-windows.yml",
    "uberagent" : None,
    "xpack-watcher": "../tools/config/winlogbeat-modules-enabled.yml",
    }

print("""
███ ███ ████ █▄┼▄█ ███ ┼┼ ███ ███ █▄█ ███ ███
█▄▄ ┼█┼ █┼▄▄ █┼█┼█ █▄█ ┼┼ █┼┼ █┼█ ███ █▄┼ █▄┼
▄▄█ ▄█▄ █▄▄█ █┼┼┼█ █┼█ ┼┼ ███ █▄█ ┼█┼ █▄▄ █┼█
                  v1.1 bugfix
please wait during the tests
""")
argparser = argparse.ArgumentParser(description="Check Sigma rules with all backend.")
argparser.add_argument("--target", "-t", choices=["yaml","json"], help="Output target format")
cmdargs = argparser.parse_args()

if cmdargs.target == None:
    print("No outpout use -h to see help")
    exit()
  
#init dict of all rules
default_key_test = {key : "NO TEST" for key in backend_dict.keys()}
the_dico ={}
rules = pathlib.Path("../rules").glob("**/*.yml")
for rule in rules:
    the_dico[rule.name] = copy.deepcopy(default_key_test)

#Check all the backend    
for name,opt in backend_dict.items():
    print (f"check backend : {name}")
    result = get_sigmac(name,opt)
    update_dict(the_dico,result,name)

#Save
if cmdargs.target.lower() == "yaml":
    cover = pathlib.Path("sigmacover.yml")
    with cover.open("w") as file:
        ruyaml.dump(the_dico, file, Dumper=ruyaml.RoundTripDumper)
else:
    cover = pathlib.Path("sigmacover.json")
    with cover.open("w") as file:
        json_dumps_str = json.dumps(the_dico, indent=4)
        file.write(json_dumps_str)
