from datetime import datetime
from sigma.collection import SigmaCollection
from typing import Iterator

PATH_TO_RULES = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]

NB_DAYS = 300


def is_experimental_and_older_than_ref(sigmaHQrule: "sigma.rule.SigmaRule") -> bool:
    last_update = sigmaHQrule.modified if sigmaHQrule.modified else sigmaHQrule.date

    return (
        str(sigmaHQrule.status) == "experimental"
        and (datetime.now().date() - last_update).days >= NB_DAYS
    )


def get_rules_to_promote() -> Iterator[str]:
    rule_paths = SigmaCollection.resolve_paths(PATH_TO_RULES)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)

    return (
        rule.source.path
        for rule in filter(is_experimental_and_older_than_ref, rule_collection)
    )


def promote_rule(rule: str) -> str:
    with open(rule, "r", encoding="utf8") as f:
        data = f.read().replace("\nstatus: experimental", "\nstatus: test")

    with open(rule, "w", encoding="utf8") as f:
        f.write(data)

    return rule


if __name__ == "__main__":
    print("\n".join(str(promote_rule(rule)) for rule in get_rules_to_promote()))
