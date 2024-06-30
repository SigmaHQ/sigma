#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create the summary of all the deprecated rules in the deprecated.csv file

Run using the command
# python deprecated_rules.py
"""

from sigma.collection import SigmaCollection
from sigma.rule import SigmaStatus,SigmaLevel
import datetime
import csv

path_to_rules = [
    "deprecated",
]
name_csv_export = "./deprecated/deprecated.csv"


def save_csv(rules):
    with open(name_csv_export, encoding="UTF-8", mode="w", newline="") as csv_file:
        fieldnames = ["id", "title", "date", "modified","level"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        raw_info = []
        for rule in rules:
            if rule.status is SigmaStatus.DEPRECATED:
                modified = rule.modified if rule.modified else datetime.date.today()
                level = rule.level if rule.status else SigmaLevel.MEDIUM
                raw_info.append(
                    {
                        "id": rule.id,
                        "title": rule.title,
                        "date": rule.date,
                        "modified": modified,
                        "level": level
                    }
                )
        
        sort_info = sorted(raw_info, key=lambda d: d['modified'])
        writer.writerows(sort_info)


if __name__ == "__main__":

    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    save_csv(rule_collection)
