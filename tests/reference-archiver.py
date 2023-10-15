# Author: Martin Spielmann / KION Group IT

__version__ = "0.0.1"

import time
import requests
import yaml
import os

# import argparse


WEB_ARCHIVE_SAVE_URL = "https://web.archive.org/save/"
WEB_ARCHIVE_GET_URL = "https://web.archive.org/web/"


def yield_next_rule_file_path(path_to_rules: str) -> str:
    for root, _, files in os.walk(path_to_rules):
        for file in files:
            yield os.path.join(root, file)


def get_rule_part(file_path: str, part_name: str):
    yaml_dicts = get_rule_yaml(file_path)
    for yaml_part in yaml_dicts:
        if not isinstance(yaml_part, dict):
            continue
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


def archive_references(path_to_rules):
    """
    Returns list of rules that leverage unknown logsource
    """
    error_archiving = []
    newly_archived_references = []

    for file in yield_next_rule_file_path(path_to_rules):
        references = get_rule_part(file_path=file, part_name="references")
        if references:
            for ref in references:
                # To avoid references using "Internal Research" or similar
                if ref.startswith("http"):
                    try:
                        archive_response = requests.get(url=WEB_ARCHIVE_GET_URL + ref)
                        # If the URL is not yet archived, the Wayback Machine returns a 404 response
                        status_code = archive_response.status_code
                        if status_code in (200, 301, 302):
                            # Already archived
                            print("Reference '{}' is already archived".format(ref))
                        elif status_code == 403:
                            # Wayback machine does not have permission to access the reference.
                            print(
                                "Wayback Machine got permission denied in the past, when trying to access reference '{}'. Not archiving.".format(
                                    ref
                                )
                            )
                        else:
                            print(
                                "Reference '{}' is not archived. Archiving...".format(
                                    ref
                                )
                            )
                            archive_response = requests.post(
                                url=WEB_ARCHIVE_SAVE_URL + ref
                            )
                            newly_archived_references.append(ref)

                        # We sleep so we don't spam the Wayback Machine too much :)
                        time.sleep(1)
                    except:
                        error_archiving.append(ref)

    return newly_archived_references, error_archiving


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(
    #    description="SIGMA Reference Archiver. Makes sure reference URLs will be available in the future by making sure they are added to the internet archive (archive.org)."
    # )
    # parser.add_argument(
    #    "-d",
    #    help="Path to input directory (SIGMA rules folder; recursive)",
    #    metavar="sigma-rules-folder",
    #    required=True,
    # )
    # args = parser.parse_args()
    #
    # if os.path.isdir(args.d):
    #    path_to_rules = args.d
    # else:
    #    print("The path provided isn't a directory: %s" % args.d)
    #    exit(1)

    print("Archiving references ...\n")

    newly_archived_references = []
    error_archiving = []

    # Archiving rules folder
    path_to_rules = "rules"
    new, error = archive_references(path_to_rules)
    newly_archived_references += new
    error_archiving += error

    # Archiving threat hunting rules folder
    path_to_rules = "rules-threat-hunting"
    new, error = archive_references(path_to_rules)
    newly_archived_references += new
    error_archiving += error

    # Archiving emerging threats rules folder
    path_to_rules = "rules-emerging-threats"
    new, error = archive_references(path_to_rules)
    newly_archived_references += new
    error_archiving += error

    # Write markdown output to open the issue
    with open(".github/archiver_output.md", "w") as f:
        f.write(
            """
            ---
            title: '"Reference Archiver Results - {{ date | date('dddd, MMMM Do') }}"'
            assignees: 'nasbench'

            ---
            \n
            """
        )
        f.write("### Archiver Script Results\n")
        f.write("#### Newly Archived References\n")

        if newly_archived_references:
            for ref in newly_archived_references:
                f.write(f"- {ref}\n")
        else:
            f.write("N/A\n")

        f.write("#### Error While Archiving References\n")
        if error_archiving:
            for ref in error_archiving:
                f.write(f"- {ref}\n")
        else:
            f.write("N/A\n")

    print("\nDone.")
