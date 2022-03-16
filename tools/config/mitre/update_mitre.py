# Updates MITRE ATT&CK tactic, technique, group and software files from the enterprise, ics and mobile bundles
# Copyright 2020-2022 Scott Dermott, Joel Perron-Langlois

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

import json
import urllib.request

mitre_source_names = frozenset(['mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack'])
software_types = frozenset(["tool", "malware"])
mitre_update_urls = dict(
    Enterprise="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    ICS="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    Mobile="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
)


def is_revoked_or_deprecated(obj: dict) -> bool:
    """ Check if the STIX object is revoked or deprecated """
    if obj.get('revoked') or obj.get('x_mitre_deprecated'):
        return True
    return False


def update_tactics(domain: str, mitre_attack: dict, tactics: dict) -> None:
    """ Parse the STIX bundle and update the tactic dictionary """
    # Map the tactics
    for entry in mitre_attack.get('objects', {}):
        if entry.get('type', "") == "x-mitre-tactic" and not is_revoked_or_deprecated(entry):
            for ref in entry.get('external_references', []):
                if isinstance(ref, dict) and ref.get('source_name', "") in mitre_source_names:
                    # Initialize the tactic
                    if not tactics.get(entry['x_mitre_shortname']):
                        tactics[entry['x_mitre_shortname']] = {}
                    # Append the domain to the tactic
                    tactics[entry['x_mitre_shortname']][domain] = {
                        'external_id': ref['external_id'],
                        'tactic': entry['name'],
                        'shortname': entry['x_mitre_shortname'],
                        'url': ref['url'],
                        'domain': [domain]
                    }
                    break


def update_techniques(domain: str, mitre_attack: dict, tactics: dict, techniques: dict) -> None:
    """ Parse the STIX bundle and update the technique dictionary """

    for entry in mitre_attack.get('objects', {}):
        if entry.get('type', "") == "attack-pattern" and not is_revoked_or_deprecated(entry):
            for ref in entry.get('external_references', []):
                if isinstance(ref, dict) and ref.get('source_name', "") in mitre_source_names:
                    # Check if technique is already in the dictionary
                    if techniques.get(ref['external_id']) and domain not in techniques[ref['external_id']]['domain']:
                        techniques[ref['external_id']]['domain'].append(domain)
                    elif techniques.get(ref['external_id']):
                        break
                    # Add technique to the dictionary
                    else:
                        # Get MITRE tactics
                        sub_tactics = []
                        for kc_phase in entry.get('kill_chain_phases', []):
                            if kc_phase.get('kill_chain_name', "") in mitre_source_names:
                                kc_phase_name = kc_phase.get('phase_name', "")
                                sub_tactic = tactics[kc_phase_name][domain]['tactic']
                                sub_tactics.append(sub_tactic)
                        # Add the technique/sub-technique
                        techniques[ref['external_id']] = {
                            'technique_id': ref['external_id'],
                            'technique': entry['name'],
                            'url': ref['url'],
                            'tactic': sub_tactics,
                            'domain': [domain],
                            'platform': entry.get('x_mitre_platforms', []),
                        }
                        break


def update_sub_technique_names(techniques: dict) -> None:
    """ Update sub-technique names with parent name as prefix """

    for technique in techniques.values():
        t_ids = technique['technique_id'].split('.')
        technique_id = t_ids[0] if len(t_ids) >= 1 else ""
        sub_technique_id = t_ids[1] if len(t_ids) >= 2 else ""

        if sub_technique_id:
            parent_t_name = techniques[technique_id]['technique']

            # Check that sub-technique name hasn't the parent name already
            if not technique['technique'].startswith(parent_t_name):
                technique['technique'] = f"{parent_t_name}: {technique['technique']}"
            else:
                print(technique['technique'])


def update_groups(domain: str, mitre_attack: dict, groups: dict) -> None:
    """ Parse the STIX bundle and update the group dictionary """

    for entry in mitre_attack.get('objects', {}):
        if entry.get('type', "") == "intrusion-set" and not is_revoked_or_deprecated(entry):
            for ref in entry.get('external_references', []):
                if isinstance(ref, dict) and ref.get('source_name', "") in mitre_source_names:
                    # Check if group is already in the dictionary
                    if groups.get(ref['external_id']) and domain not in groups[ref['external_id']]['domain']:
                        groups[ref['external_id']]['domain'].append(domain)
                    elif groups.get(ref['external_id']):
                        break
                    # Add group to the dictionary
                    else:
                        groups[ref['external_id']] = {
                            'group_id': ref['external_id'],
                            'group': entry['name'],
                            'url': ref['url'],
                            'domain': [domain]
                        }
                        break


def update_software(domain: str, mitre_attack: dict, software: dict) -> None:
    """ Parse the STIX bundle and update the software dictionary """

    for entry in mitre_attack.get('objects', {}):
        if entry.get('type', "") in software_types and not is_revoked_or_deprecated(entry):
            for ref in entry.get('external_references', []):
                if isinstance(ref, dict) and ref.get('source_name', "") in mitre_source_names:
                    # Check if software is already in the dictionary
                    if software.get(ref['external_id']) and \
                            domain not in software[ref['external_id']]['domain']:
                        software[ref['external_id']]['domain'].append(domain)
                    elif software.get(ref['external_id']):
                        break
                    # Add software to the dictionary
                    else:
                        software[ref['external_id']] = {
                            'software_id': ref['external_id'],
                            'software': entry['name'],
                            'type': entry['type'].capitalize(),
                            'url': ref['url'],
                            'domain': [domain],
                            'platform': entry.get('x_mitre_platforms', [])
                        }
                        break


def format_tactics_output(tactics: dict) -> list:
    """ Format the tactic data for easier output """

    tactics_formatted = []
    for tactic in tactics.values():
        for domain in tactic.values():
            tactics_formatted.append(domain)

    tactics_formatted.sort(key=lambda ta: ta['external_id'])
    return tactics_formatted


def format_output(sort_field: str, data: dict) -> list:
    """ Format the MITRE ATT&CK data for easier output """
    data_formatted = []
    for entry in data.values():
        data_formatted.append(entry)

    data_formatted.sort(key=lambda s: s[sort_field])
    return data_formatted


def print_results(tactics: list, techniques: list, groups: list, software: list) -> None:
    """ Count and print to console MITRE ATT&CK type count """

    def _init_or_add_domain(dom: str, res: dict) -> None:
        res[dom] = res[dom] + 1 if dom in res else 1

    def _calc_results_per_domain(res: dict, data: list) -> None:
        for entry in data:
            for domain in entry['domain']:
                _init_or_add_domain(dom=domain, res=res)

    def _print_results_per_domain(mitre_type: str, data: list, res: dict) -> None:
        print(f"Total unique MITRE ATT&CK {mitre_type}: {len(data)}")
        for domain, count in res.items():
            print(f"\tTotal MITRE ATT&CK - {domain} {mitre_type}: {count}")

    # Count number of MITRE ATT&CK types
    res_tactics, res_techniques, res_groups, res_software = {}, {}, {}, {}
    _calc_results_per_domain(res=res_tactics, data=tactics)
    _calc_results_per_domain(res=res_techniques, data=techniques)
    _calc_results_per_domain(res=res_groups, data=groups)
    _calc_results_per_domain(res=res_software, data=software)

    # Print to console the results
    _print_results_per_domain(mitre_type="tactics", data=tactics, res=res_tactics)
    _print_results_per_domain(mitre_type="techniques and sub-techniques", data=techniques, res=res_techniques)
    _print_results_per_domain(mitre_type="groups", data=groups, res=res_groups)
    _print_results_per_domain(mitre_type="software", data=software, res=res_software)


def create_output_file(filename: str, data: list) -> None:
    """ Create JSON output file with the MITRE ATT&CK data """
    with open(file=filename, mode='w') as json_file:
        json.dump(obj=data, fp=json_file, sort_keys=False, indent=2)


def main():
    tactics, techniques, software, groups = {}, {}, {}, {}

    # Download and parse MITRE ATT&CK STIX domain bundles
    for domain, url in mitre_update_urls.items():
        with urllib.request.urlopen(url) as cti_json:
            mitre_json = json.loads(cti_json.read().decode())

            # Parse MITRE ATT&CK STIX data and update the dictionaries
            update_tactics(domain=domain, mitre_attack=mitre_json, tactics=tactics)
            update_techniques(domain=domain, mitre_attack=mitre_json, tactics=tactics, techniques=techniques)
            update_groups(domain=domain, mitre_attack=mitre_json, groups=groups)
            update_software(domain=domain, mitre_attack=mitre_json, software=software)

    # Add the technique names in front their sub-technique names
    update_sub_technique_names(techniques=techniques)

    # Create lists to output
    formatted_tactics = format_tactics_output(tactics=tactics)
    formatted_techniques = format_output(sort_field="technique_id", data=techniques)
    formatted_groups = format_output(sort_field="group_id", data=groups)
    formatted_software = format_output(sort_field="software_id", data=software)

    # Print MITRE ATT&CK type count per domain
    print_results(tactics=formatted_tactics, techniques=formatted_techniques,
                  groups=formatted_groups, software=formatted_software)

    # Output MITRE ATT&CK types to files
    create_output_file(filename="tactics.json", data=formatted_tactics)
    create_output_file(filename="techniques.json", data=formatted_techniques)
    create_output_file(filename="groups.json", data=formatted_groups)
    create_output_file(filename="software.json", data=formatted_software)


if __name__ == "__main__":
    main()
