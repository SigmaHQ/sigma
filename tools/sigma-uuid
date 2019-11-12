#!/usr/bin/env python3
# Assign UUIDs to Sigma rules and verify UUID assignment for a Sigma rule repository

from argparse import ArgumentParser
from pathlib import Path
from uuid import uuid4, UUID
import yaml
from sigma.output import SigmaYAMLDumper

argparser = ArgumentParser(description="Assign and verfify UUIDs of Sigma rules")
argparser.add_argument("--verify", "-V", action="store_true", help="Verify existence and uniqueness of UUID assignments. Exits with error code if verification fails.")
argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose.")
argparser.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories.")
argparser.add_argument("--error", "-e", action="store_true", help="Exit with error code 10 on verification failures.")
argparser.add_argument("inputs", nargs="+", help="Sigma rule files or repository directories")
args = argparser.parse_args()

if args.recursive:
    paths = [ p for pathname in args.inputs for p in Path(pathname).glob("**/*") if p.is_file() ]
else:
    paths = [ Path(pathname) for pathname in args.inputs ]

def print_verbose(*arg, **kwarg):
    if args.verbose:
        print(*arg, **kwarg)

# Define order-preserving representer from dicts/maps
def yaml_preserve_order(self, dict_data):
    return self.represent_mapping("tag:yaml.org,2002:map", dict_data.items())

yaml.add_representer(dict, yaml_preserve_order)

uuids = set()
passed = True
for path in paths:
    print_verbose("Rule {}".format(str(path)))
    with path.open("r") as f:
        rules = list(yaml.safe_load_all(f))

    if args.verify:
        i = 1
        for rule in rules:
            if "title" in rule:     # Rule with a title should also have a UUID
                try:
                    UUID(rule["id"])
                except ValueError:  # id is not a valid UUID
                    print("Rule {} in file {} has a malformed UUID '{}'.".format(i, str(path), rule["id"]))
                    passed = False
                except KeyError:    # rule has no id
                    print("Rule {} in file {} has no UUID.".format(i, str(path)))
                    passed = False
            i += 1
    else:
        newrules = list()
        changed = False
        i = 1
        for rule in rules:
            if "title" in rule and "id" not in rule:    # only assign id to rules that have a title and no id
                newrule = dict()
                changed = True
                for k, v in rule.items():
                    newrule[k] = v
                    if k == "title":    # insert id after title
                        uuid = uuid4()
                        newrule["id"] = str(uuid)
                        print("Assigned UUID '{}' to rule {} in file {}.".format(uuid, i, str(path)))
                newrules.append(newrule)
            else:
                newrules.append(rule)
            i += 1

        if changed:
            with path.open("w") as f:
                yaml.dump_all(newrules, f, Dumper=SigmaYAMLDumper, indent=4, width=160, default_flow_style=False)

if not passed:
    print("The Sigma rules listed above don't have an ID. The ID must be:")
    print("* Contained in the 'id' attribute")
    print("* a valid UUIDv4 (randomly generated)")
    print("* Unique in this repository")
    print("Please generate one with the sigma-uuid tool or here: https://www.uuidgenerator.net/version4")
    if args.error:
        exit(10)
