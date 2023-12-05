# Author:
#    Martin Spielmann / KION Group IT
#    Nasreddine Bencherchali / Nextron Systems

__version__ = "0.0.1"

import time
import requests
import yaml
import os
from datetime import datetime


WEB_ARCHIVE_SAVE_URL = "https://web.archive.org/save/"
WEB_ARCHIVE_GET_URL = "https://web.archive.org/web/"

with open("tests/rule-references.txt", "r") as f:
    RULE_REFERENCES = [i.strip() for i in f.readlines()]

path_to_rules = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]


# Helper functions
def yield_next_rule_file_path(path_to_rules: list) -> str:
    for path_ in path_to_rules:
        for root, _, files in os.walk(path_):
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

    with open(file_path, encoding="utf-8") as f:
        yaml_parts = yaml.safe_load_all(f)
        for part in yaml_parts:
            data.append(part)

    return data


def get_references(path_to_rules):
    ref_list = []

    for file in yield_next_rule_file_path(path_to_rules):
        references = get_rule_part(file_path=file, part_name="references")
        if references:
            for ref in references:
                # To avoid references using "Internal Research" or similar
                if ref.startswith("http"):
                    ref_list.append(ref)
    return ref_list


def archive_references(ref_list):
    error_archiving = []
    already_archived = []
    newly_archived_references = []

    for ref in ref_list:
        try:
            archive_response = requests.get(url=WEB_ARCHIVE_GET_URL + ref)
            # If the URL is not yet archived, the Wayback Machine returns a 404 response
            status_code = archive_response.status_code
            if status_code in (200, 301, 302):
                # Already archived
                already_archived.append(ref)
                print("Reference '{}' is already archived".format(ref))
            elif status_code == 403:
                # Wayback machine does not have permission to access the reference.
                error_archiving.append(ref)
                print(
                    "Wayback Machine got permission denied in the past, when trying to access reference '{}'. Not archiving.".format(
                        ref
                    )
                )
            else:
                print("Reference '{}' is not archived. Archiving...".format(ref))
                archive_response = requests.post(url=WEB_ARCHIVE_SAVE_URL + ref)
                newly_archived_references.append(ref)

            # We sleep so we don't spam the Wayback Machine too much :)
            time.sleep(1)
        except:
            error_archiving.append(ref)

    return already_archived, newly_archived_references, error_archiving


if __name__ == "__main__":
    print("Archiving references ...\n")

    tmp_ref_list = get_references(path_to_rules)

    # We do an intersection between the full list and the list of references that are already archived
    ref_list = list(set(tmp_ref_list) - set(RULE_REFERENCES))

    already_archived, newly_archived_references, error_archiving = archive_references(
        ref_list
    )

    with open("tests/rule-references.txt", "a") as f:
        for ref in already_archived:
            f.write(ref)
            f.write("\n")

        for ref in newly_archived_references:
            f.write(ref)
            f.write("\n")

    # Write markdown output to open the issue
    with open(".github/latest_archiver_output.md", "w") as f:
        f.write(f"# Reference Archiver Results\n\n")
        f.write(f"Last Execution: {datetime.today().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("### Archiver Script Results\n\n")
        f.write("\n#### Newly Archived References\n\n")
        if newly_archived_references:
            for ref in newly_archived_references:
                f.write(f"- {ref}\n")
        else:
            f.write("N/A\n")

        f.write("\n#### Already Archived References\n\n")
        if already_archived:
            for ref in already_archived:
                f.write(f"- {ref}\n")
        else:
            f.write("N/A\n")

        f.write("\n#### Error While Archiving References\n\n")
        if error_archiving:
            for ref in error_archiving:
                f.write(f"- {ref}\n")
        else:
            f.write("N/A\n")

    print("\nDone.")
