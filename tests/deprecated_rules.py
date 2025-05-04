#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create the summary of all the deprecated rules in the deprecated.csv file

Run using the command
# python deprecated_rules.py
"""

from sigma.collection import SigmaCollection
from sigma.rule import SigmaStatus,SigmaLevel

import argparse
import datetime
import csv

parser = argparse.ArgumentParser()
parser.add_argument('-f',  '--format', choices=['csv'], default='csv')
args = parser.parse_args()

path_to_rules = [
    "deprecated",
]

def get_level(rule):
    return rule.level if rule.status else SigmaLevel.MEDIUM

def get_modified_time(rule):
    return rule.modified if rule.modified else datetime.date.today()

def format_rule(rule):
    return {
        "id": str(rule.id),
        "title": rule.title,
        "date": str(rule.date),
        "modified": str(get_modified_time(rule)),
        "level": str(get_level(rule))
    }

def save_csv(rules):
    is_rule_deprecated = lambda rule: rule.status is SigmaStatus.DEPRECATED
    name_csv_export = f"./deprecated/deprecated.{args.format}"

    raw_info = map(format_rule, filter(is_rule_deprecated, rules))
    sort_info = sorted(raw_info, key=lambda d: d['modified'])

    with open(name_csv_export, encoding="UTF-8", mode="w", newline="") as csv_file:
        if args.format == "csv":
            fieldnames = ["id", "title", "date", "modified","level"]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sort_info)

if __name__ == "__main__":

    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    save_csv(rule_collection)
