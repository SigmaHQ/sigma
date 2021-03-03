#!/usr/bin/env python3

import argparse
import glob
import json
import os
import sys

import yaml

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--rules-directory", "-d", dest="rules_dir", default="rules", help="Directory to read rules from")
    parser.add_argument("--out-file", "-o", dest="out_file", default="heatmap.json", help="File to write the JSON layer to")
    parser.add_argument("--no-comment", dest="no_comment", action="store_true", help="Don't store rule names in comments")
    args = parser.parse_args()

    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.yml"), recursive=True)
    techniques_to_rules = {}
    curr_max_technique_count = 0
    num_rules_used = 0
    for rule_file in rule_files:
        try:
            rule = yaml.safe_load(open(rule_file, encoding="utf-8").read())
        except yaml.YAMLError:
            sys.stderr.write("Ignoring rule " + rule_file + " (parsing failed)\n")
            continue
        if "tags" not in rule:
            sys.stderr.write("Ignoring rule " + rule_file + " (no tags)\n")
            continue
        tags = rule["tags"]
        for tag in tags:
            if tag.lower().startswith("attack.t"):
                technique_id = tag[len("attack."):].upper()
                num_rules_used += 1
                if technique_id not in techniques_to_rules:
                    techniques_to_rules[technique_id] = []
                techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                curr_max_technique_count = max(curr_max_technique_count, len(techniques_to_rules[technique_id]))


    scores = []
    for technique in techniques_to_rules:
        entry = {
            "techniqueID": technique, 
            "score": len(techniques_to_rules[technique]), 
        }
        if not args.no_comment:
            entry["comment"] = "\n".join(techniques_to_rules[technique])

        scores.append(entry)

    output = {
        "domain": "mitre-enterprise",
        "name": "Sigma rules heatmap",
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff6666"
            ],
            "maxValue": curr_max_technique_count,
            "minValue": 0
        },
        "versions": {
            "navigator": "4.0",
            "layer": "4.0"
        },
        "techniques": scores,
    }

    with open(args.out_file, "w") as f:
        f.write(json.dumps(output))
        print("[*] Layer file written in " + args.out_file + " (" + str(num_rules_used) + " rules)")

if __name__ == "__main__":
    main()
