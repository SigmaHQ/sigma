# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: sigmacover.py
Date: 26/09/2021
Author: frack113
Version: 1.0
Description: 
    get cover of the rules vs backend
    It is more a POC than a script for the moment
Requirements:
    $ pip install ruyaml
Todo:
    - add output options
    - clean code and bug
    - better use of subprocess.run
    - have idea
"""


import re
import subprocess
import pathlib
import ruyaml


def get_sigmac(options):
    infos = []
    ret = subprocess.run(options,)
    log = pathlib.Path("sigmac.log")
    with log.open() as f:
        lines = f.readlines()
        for line in lines:
            if "Convertion Sigma input" in line:
                info = re.findall("Convertion Sigma input \S+\\\\(\w+\.yml) (\w+)",line)[0]
                infos.append(info)
    log.unlink()
    return infos            

def update_dict(my_dict,my_data,backend):
    for file,state in my_data:
        my_dict[file][backend] = state

#the backend dict command line options
backend_dict = {
    "ala" : ["python","../tools/sigmac","-t","ala","--debug","-rI","../rules"],
    "ala-rule" : ["python","../tools/sigmac","-t","ala-rule","--debug","-rI","../rules"],
    "arcsight": ["python","../tools/sigmac","-t","arcsight","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "arcsight-esm": ["python","../tools/sigmac","-t","arcsight-esm","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "carbonblack": ["python","../tools/sigmac","-t","carbonblack","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "chronicle": ["python","../tools/sigmac","-t","chronicle","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "crowdstrike": ["python","../tools/sigmac","-t","crowdstrike","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "csharp" : ["python","../tools/sigmac","-t","csharp","--debug","-rI","../rules"],
    "devo": ["python","../tools/sigmac","-t","devo","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "ee-outliers": ["python","../tools/sigmac","-t","ee-outliers","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "elastalert": ["python","../tools/sigmac","-t","elastalert","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "elastalert-dsl": ["python","../tools/sigmac","-t","elastalert-dsl","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-dsl": ["python","../tools/sigmac","-t","es-dsl","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-eql": ["python","../tools/sigmac","-t","es-eql","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-qs": ["python","../tools/sigmac","-t","es-qs","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-qs-lr": ["python","../tools/sigmac","-t","es-qs-lr","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-rule": ["python","../tools/sigmac","-t","es-rule","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "es-rule-eql": ["python","../tools/sigmac","-t","es-rule-eql","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "fireeye-helix": ["python","../tools/sigmac","-t","fireeye-helix","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "graylog" : ["python","../tools/sigmac","-t","graylog","--debug","-rI","../rules"],
    "grep" : ["python","../tools/sigmac","-t","grep","--debug","-rI","../rules"],
    "humio": ["python","../tools/sigmac","-t","humio","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "kibana": ["python","../tools/sigmac","-t","kibana","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "kibana-ndjson": ["python","../tools/sigmac","-t","kibana-ndjson","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "lacework" : ["python","../tools/sigmac","-t","lacework","--debug","-rI","../rules"],
    "limacharlie" : ["python","../tools/sigmac","-t","limacharlie","--debug","-rI","../rules"],
    "logiq" : ["python","../tools/sigmac","-t","logiq","--debug","-rI","../rules"],
    "logpoint" : ["python","../tools/sigmac","-t","logpoint","--debug","-rI","../rules"],
    "mdatp" : ["python","../tools/sigmac","-t","mdatp","--debug","-rI","../rules"],
    "netwitness" : ["python","../tools/sigmac","-t","netwitness","--debug","-rI","../rules"],
    "netwitness-epl" : ["python","../tools/sigmac","-t","netwitness-epl","--debug","-rI","../rules"],
    "opensearch-monitor": ["python","../tools/sigmac","-t","opensearch-monitor","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    "powershell" : ["python","../tools/sigmac","-t","powershell","--debug","-rI","../rules"],
    "qradar" : ["python","../tools/sigmac","-t","qradar","--debug","-rI","../rules"],
    "qualys" : ["python","../tools/sigmac","-t","qualys","--debug","-rI","../rules"],
    "sentinel-rule" : ["python","../tools/sigmac","-t","sentinel-rule","--debug","-rI","../rules"],
    "splunk": ["python","../tools/sigmac","-t","splunk","-c","../tools/config/splunk-windows.yml","--debug","-rI","../rules"],
    "splunkdm": ["python","../tools/sigmac","-t","splunkdm","-c","../tools/config/splunk-windows.yml","--debug","-rI","../rules"],
    "splunkxml": ["python","../tools/sigmac","-t","splunkxml","-c","../tools/config/splunk-windows.yml","--debug","-rI","../rules"],
    "sql": ["python","../tools/sigmac","-t","sql","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "sqlite": ["python","../tools/sigmac","-t","sqlite","-c","../tools/config/elk-winlogbeat.yml","--debug","-rI","../rules"],
    "stix": ["python","../tools/sigmac","-t","stix","-c","../tools/config/stix2.0.yml","--debug","-rI","../rules"],
    "sumologic" : ["python","../tools/sigmac","-t","sumologic","--debug","-rI","../rules"],
    "sumologic-cse" : ["python","../tools/sigmac","-t","sumologic-cse","--debug","-rI","../rules"],
    "sumologic-cse-rule" : ["python","../tools/sigmac","-t","sumologic-cse-rule","--debug","-rI","../rules"],
    "sysmon": ["python","../tools/sigmac","-t","stix","-c","../tools/config/sysmon.yml","--debug","-rI","../rules"],
    "uberagent" : ["python","../tools/sigmac","-t","uberagent","--debug","-rI","../rules"],
    "xpack-watcher": ["python","../tools/sigmac","-t","xpack-watcher","-c","../tools/config/winlogbeat.yml","--debug","-rI","../rules"],
    }

print("""
███ ███ ████ █▄┼▄█ ███ ┼┼ ███ ███ █▄█ ███ ███
█▄▄ ┼█┼ █┼▄▄ █┼█┼█ █▄█ ┼┼ █┼┼ █┼█ ███ █▄┼ █▄┼
▄▄█ ▄█▄ █▄▄█ █┼┼┼█ █┼█ ┼┼ ███ █▄█ ┼█┼ █▄▄ █┼█
                    v1.0
please wait during the tests
""")

#init dict of all rules
default_key_test = {key : "NO TEST" for key in backend_dict.keys()}
the_dico ={}
rules = pathlib.Path("../rules").glob("**/*.yml")
for rule in rules:
    the_dico[rule.name] = default_key_test

#Check all the backend    
for name,opt in backend_dict.items():
    print (f"check backend : {name}")
    result = get_sigmac(opt)
    update_dict(the_dico,result,name)

#Save
cover = pathlib.Path("sigmacover.yml")
with cover.open("w") as f:
    ruyaml.dump(the_dico, f, Dumper=ruyaml.RoundTripDumper)

