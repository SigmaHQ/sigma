from collections import defaultdict
from datetime import datetime
from functools import reduce
from sigma.collection import SigmaCollection
from typing import Iterator
import json
import os

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


def summarize_promotion(summary: dict, rule: str) -> dict:
    key, *values = rule.split(os.sep)
    value = os.sep.join(values)
    summary[key].append(value)

    return summary


if __name__ == "__main__":
    rules = (str(promote_rule(rule)) for rule in get_rules_to_promote())
    promotion = reduce(summarize_promotion, rules, defaultdict(list))

    print(json.dumps(promotion))
