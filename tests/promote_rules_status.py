from datetime import datetime
from sigma.collection import SigmaCollection

path_to_rules = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]


def get_rules_to_promote():
    today = datetime.today().strftime("%Y/%m/%d")
    rules_to_promote = []

    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    for sigmaHQrule in rule_collection:
        if str(sigmaHQrule.status) == "experimental":
            last_update = (
                sigmaHQrule.modified if sigmaHQrule.modified else sigmaHQrule.date
            )
            last_update = last_update.strftime("%Y/%m/%d")
            difference = (
                datetime.strptime(today, "%Y/%m/%d")
                - datetime.strptime(last_update, "%Y/%m/%d")
            ).days
            if difference >= 300:
                rules_to_promote.append(sigmaHQrule.source.path)

    return rules_to_promote


def promote_rules(rules_to_promote):
    for file_ in rules_to_promote:
        with open(file_, "r", encoding="utf8") as f:
            data = f.read().replace("\nstatus: experimental", "\nstatus: test")

        with open(file_, "w", encoding="utf8") as f:
            f.write(data)


if __name__ == "__main__":
    rules_to_promote = get_rules_to_promote()
    promote_rules(rules_to_promote)
