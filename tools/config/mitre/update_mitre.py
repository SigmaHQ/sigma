# Updates the Mitre Tactics & Techniques from Mitre CTI Pre, Enterprise & Mobile Attack
# Copyright 2020 Scott Dermott

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

import os
import json
import urllib.request 

mitre_update_urls = [
    'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json',
    'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'
]
mitre_source_types = list([
    'mitre-pre-attack',
    'mitre-attack',
    'mitre-mobile-attack'
])
tactics_list = []
techniques_list = []

def get_external_id(obj):
    return obj.get('external_id')
    
def get_technique_id(obj):
    return obj.get('technique_id')

def revoked_or_deprecated(entry):
    if "revoked" in entry.keys() and entry['revoked'] or "x_mitre_deprecated" in entry.keys() and entry['x_mitre_deprecated']:
        return True
    return False

for url in mitre_update_urls:
    with urllib.request.urlopen(url) as cti_json:
        mitre_json = json.loads(cti_json.read().decode())
        url_type = url.rsplit('/',1)[1].split('.')[0].title()
        techniques = []
        tactics = []
        tactic_map = {}
        technique_map = {}

        # Map the tatics
        for entry in mitre_json['objects']:
            if not entry['type'] == "x-mitre-tactic" or revoked_or_deprecated(entry):
                continue
            for ref in entry['external_references']:
                if ref['source_name'] in mitre_source_types:
                    tactic_map[entry['x_mitre_shortname']] = entry['name']
                    tactics.append({
                        "external_id": ref['external_id'],
                        "url": ref['url'],
                        "tactic": entry['name']
                    })
                    break

        # Map the techniques
        for entry in mitre_json['objects']:
            if not entry['type'] == "attack-pattern" or revoked_or_deprecated(entry):
                continue
            if "x_mitre_is_subtechnique" in entry.keys() and entry['x_mitre_is_subtechnique']:
                continue
            for ref in entry['external_references']:
                if ref['source_name'] in mitre_source_types:
                    technique_map[ref['external_id']] = entry['name']
                    sub_tactics = []
                    # Get Mitre Tactics (Kill-Chains)
                    for tactic in entry['kill_chain_phases']:
                        if tactic['kill_chain_name'] in mitre_source_types:
                            # Map the short phase_name to tactic name
                            sub_tactics.append(tactic_map[tactic['phase_name']])
                    techniques.append({
                        "technique_id": ref['external_id'],
                        "technique": entry['name'],
                        "url": ref['url'],
                        "tactic" : sub_tactics
                    })
                    break

        ## Map the sub-techniques
        for entry in mitre_json['objects']:
            if not entry['type'] == "attack-pattern" or revoked_or_deprecated(entry):
                continue
            if "x_mitre_is_subtechnique" in entry.keys() and entry['x_mitre_is_subtechnique']:
                for ref in entry['external_references']:
                    if ref['source_name'] in mitre_source_types:
                        sub_technique_id = ref['external_id']
                        sub_technique_name = entry['name']
                        parent_technique_name = technique_map[sub_technique_id.split('.')[0]]
                        sub_technique_name = '{} : {}'.format(parent_technique_name, sub_technique_name)
                        techniques.append({
                            "technique_id": ref['external_id'],
                            "technique": sub_technique_name,
                            "url": ref['url'],
                        })
                        break

        print("Updating from : {}".format(url))
        print("{} Mitre Bundle ID : {} ".format(url_type, mitre_json['id']))
        print("{} Tactics : {} ".format(url_type, len(tactic_map)))
        print("{} Techniques : {} ".format(url_type, len(technique_map)))
        print("{} Sub-Techniques : {} ".format(url_type, len(techniques) - len(technique_map)))
        print("-------------------------------------------------")
        tactics_list.extend(tactics)
        techniques_list.extend(techniques)

print("Total Mitre Tactics : {} ".format(len(tactics_list)))
print("Total Mitre Techniques : {} ".format(len(techniques_list)))
## Create the output files
with open('tactics.json', 'w') as json_file:
    tactics_list.sort(key=get_external_id)
    json.dump(tactics_list, json_file, sort_keys=False, indent=2)

with open('techniques.json', 'w') as json_file:
    techniques_list.sort(key=get_technique_id)
    json.dump(techniques_list, json_file, sort_keys=False, indent=2)