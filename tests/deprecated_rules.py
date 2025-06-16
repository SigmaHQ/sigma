#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create the summary of all the deprecated rules in deprecated.csv or deprecated.json

Run using the command
# python deprecated_rules.py --format {json, csv}
"""

from sigma.collection import SigmaCollection
from sigma.rule import SigmaStatus, SigmaLevel

import argparse
import csv
import json

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv")
args = parser.parse_args()

path_to_rules = [
    "deprecated",
]


def get_level(rule):
    return rule.level if rule.status else SigmaLevel.MEDIUM


def get_modified_time(rule):
    return rule.modified if rule.modified else rule.date


def format_rule(rule):
    return {
        "id": str(rule.id),
        "title": rule.title,
        "date": str(rule.date),
        "modified": str(get_modified_time(rule)),
        "level": str(get_level(rule)),
    }


def save_file(rules, _format):
    is_rule_deprecated = lambda rule: rule.status is SigmaStatus.DEPRECATED
    filename_export = f"./deprecated/deprecated.{_format}"

    raw_info = map(format_rule, filter(is_rule_deprecated, rules))
    sort_info_secondary = sorted(raw_info, key=lambda d: d["id"])
    sort_info = sorted(sort_info_secondary, key=lambda d: d["modified"])

    with open(filename_export, encoding="UTF-8", mode="w", newline="") as _file:
        if _format == "csv":
            fieldnames = ["id", "title", "date", "modified", "level"]
            writer = csv.DictWriter(_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sort_info)
        elif _format == "json":
            json.dump(sort_info, _file, indent=4)


if __name__ == "__main__":

    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    save_file(rule_collection, args.format)
