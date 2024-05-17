#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create the summary of all the deprecated rules in the deprecated.csv file

Run using the command
# python deprecated_rules.py
"""

from sigma.collection import SigmaCollection
import csv

path_to_rules = [
    "deprecated",
]
name_csv_export = "./deprecated/deprecated.csv"


def save_csv(rules):
    with open(name_csv_export, encoding="UTF-8", mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        info = []
        info.append(["Rule ID", "Title", "Date", "Modified"])
        for rule in rules:
            info.append([rule.id, rule.title, rule.date, rule.modified])
        writer.writerows(info)


if __name__ == "__main__":

    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    save_csv(rule_collection)
