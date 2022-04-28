#!/usr/bin/env python3

import argparse
import glob
import json
import os
import sys

import yaml

level_eq = {
    "informational" : 1,
    "low"           : 2,
    "medium"        : 3,
    "high"          : 4,
    "critical"      : 5
    }

status_eq = {
    "unsupported"   : 1,
    "deprecated"    : 2,
    "experimental"  : 3,
    "test"          : 4,
    "stable"        : 5
        }

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--rules-directory", "-d", dest="rules_dir", default="rules", help="Directory to read rules from")
    parser.add_argument("--out-file", "-o", dest="out_file", default="heatmap.json", help="File to write the JSON layer to")
    parser.add_argument("--no-comment", dest="no_comment", action="store_true", help="Don't store rule names in comments")
    parser.add_argument("--status-start", "-s",dest="status_start", default="unsupported", help="Check rule with minimun status")
    parser.add_argument("--status-end", "-se",dest="status_end", default="stable", help="Check rule with maximun status")
    parser.add_argument("--level-score", "-l",dest="level_score", action="store_true", help="Score depand form rule level")


    args = parser.parse_args()
    print(args.level_score)
    status_start = status_eq[args.status_start]
    status_end = status_eq[args.status_end]

    rule_files = glob.glob(os.path.join(args.rules_dir, "**/*.yml"), recursive=True)
    techniques_to_rules = {}
    score_to_rules = {}
    curr_max_technique_count = 0
    num_rules_used = 0
    num_rules_no_tags = 0
    num_rules_no_techniques = 0
    for rule_file in rule_files:
        with open(rule_file,encoding='utf-8') as f:
            docs = yaml.load_all(f, Loader=yaml.FullLoader)
            double = False
            for rule in docs:
                if "tags" not in rule :
                    if double == False : # Only 1 warning
                        sys.stderr.write(f"Ignoring rule {rule_file} (no tags)\n")
                        num_rules_no_tags += 1
                    double = True # action globle no tag
                    continue
                if not "status" in rule:
                    status_name = "experimental"
                else:
                    status_name = rule["status"]
                status_nb = status_eq[status_name]
                if status_nb <status_start or status_nb>status_end:
                    sys.stderr.write(f"Ignoring rule {rule_file} filter status : {status_name}\n")
                    continue
                tags = rule["tags"]
                level = rule["level"]
                double = True
                t_tags = False
                for tag in tags:
                    if tag.lower().startswith("attack.t"):
                        t_tags = True
                        technique_id = tag[len("attack."):].upper()
                        num_rules_used += 1
                        if technique_id not in techniques_to_rules:
                            techniques_to_rules[technique_id] = []
                            score_to_rules[technique_id] = []
                        techniques_to_rules[technique_id].append(os.path.basename(rule_file))
                        score_to_rules[technique_id].append(level_eq[level])
                        if args.level_score == True:
                            curr_max_technique_count = max(curr_max_technique_count, sum(score_to_rules[technique_id]))
                        else:
                            curr_max_technique_count = max(curr_max_technique_count, len(techniques_to_rules[technique_id]))
                if t_tags == False:
                    sys.stderr.write(f"Ignoring rule {rule_file} no Techniques in {tags} \n")
                    num_rules_no_techniques += 1

    scores = []
    for technique in techniques_to_rules:
        if args.level_score == True:
            technique_score = sum(score_to_rules[technique])
        else:
            technique_score = len(techniques_to_rules[technique])
        entry = {
            "techniqueID": technique, 
            "score": technique_score, 
        }
        if not args.no_comment:
            entry["comment"] = "\n".join(techniques_to_rules[technique])

        scores.append(entry)

    output = {
        "name": "Sigma rules heatmap",
        "versions": {
            "attack": "10",
            "navigator": "4.4.4",
            "layer": "4.2"
        },
        "domain": "enterprise-attack",
        "description": "Sigma rules heatmap",
        "gradient": {
		    "colors": [
			    "#66b1ffff",
			    "#ff66f4ff",
			    "#ff6666ff"
		    ],
            "maxValue": curr_max_technique_count,
            "minValue": 0
        },

        "techniques": scores,
    }

    with open(args.out_file, "w",encoding="UTF-8") as f:
        f.write(json.dumps(output, indent=4, ensure_ascii=False))
        print(f"[*] Layer file written in {args.out_file} ({str(num_rules_used)} rules)")
        if num_rules_no_tags>0 :
            print(f"[-] Ignored  {num_rules_no_tags} rules without tags")
        else:
            print(f"[*] No rule without tags")
        if num_rules_no_techniques>0:
            print(f"[-] Ignored {num_rules_no_techniques} rules whitout Mitre Technique")
        else:
            print(f"[*] No rule whitout Mitre Technique")

if __name__ == "__main__":
    main()
