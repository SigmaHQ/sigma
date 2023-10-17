import os
import yaml
from datetime import datetime

path_to_rules_ = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]
path_to_rules = []
for path_ in path_to_rules_:
    path_to_rules.append(
        os.path.join(os.path.dirname(os.path.realpath(__name__)), path_)
    )


# Helper functions
def yield_next_rule_file_path(path_to_rules: list) -> str:
    for path_ in path_to_rules:
        for root, _, files in os.walk(path_):
            for file in files:
                if file.endswith(".yml"):
                    yield os.path.join(root, file)


def get_rule_yaml(file_path: str) -> dict:
    data = []

    with open(file_path, encoding="utf-8") as f:
        yaml_parts = yaml.safe_load_all(f)
        for part in yaml_parts:
            data.append(part)

    return data


def get_rule_part(file_path: str, part_name: str):
    yaml_dicts = get_rule_yaml(file_path)
    for yaml_part in yaml_dicts:
        if part_name in yaml_part.keys():
            return yaml_part[part_name]

    return None


def get_rules_to_promote():
    today = datetime.today().strftime("%Y/%m/%d")
    rules_to_promote = []
    for file in yield_next_rule_file_path(path_to_rules):
        status = get_rule_part(file_path=file, part_name="status")
        if status:
            if status == "experimental":
                last_update = ""
                date_ = get_rule_part(file_path=file, part_name="date")
                modified_ = get_rule_part(file_path=file, part_name="modified")
                if modified_:
                    last_update = modified_
                elif date_:
                    last_update = date_
                else:
                    # We assign today as a last option to avoid any errors
                    last_update = today

                difference = (
                    datetime.strptime(today, "%Y/%m/%d")
                    - datetime.strptime(last_update, "%Y/%m/%d")
                ).days
                if difference >= 300:
                    rules_to_promote.append(file)
    return rules_to_promote


def promote_rules(rules_to_promote):
    for file_ in rules_to_promote:
        with open(file_, "r", encoding="utf8") as f:
            data = f.read().replace("status: experimental", "status: test")

        with open(file_, "w", encoding="utf8") as f:
            f.write(data)


if __name__ == "__main__":
    rules_to_promote = get_rules_to_promote()
    promote_rules(rules_to_promote)
