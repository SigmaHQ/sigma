#!/usr/bin/env python3
# Assign UUIDs to Sigma rules and verify UUID assignment for a Sigma rule repository
# Copyright 2016-2021 SigmaHQ

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from argparse import ArgumentParser
from pathlib import Path
from uuid import uuid4, UUID
import ruamel.yaml
from sigma.output import SigmaYAMLDumper


def print_verbose(*arg, **kwarg):
    print(*arg, **kwarg)

# Define order-preserving representer from dicts/maps
def yaml_preserve_order(self, dict_data):
    return self.represent_mapping("tag:yaml.org,2002:map", dict_data.items())

def valid_id(rule,i,path):
    try:
        UUID(rule["id"])
    except ValueError:  # id is not a valid UUID
        print("Rule {} in file {} has a malformed UUID '{}'.".format(i, str(path), rule["id"]))
        return False
    except KeyError:    # rule has no id
        print("Rule {} in file {} has no UUID.".format(i, str(path)))
        return False
    return True 

def is_global(rule):
    if 'action' in rule:
        if rule['action'] == 'global':
            return True
    return False

def is_id_uuid(rule):
    if 'id' in rule:
        try:
            UUID(rule["id"])
        except ValueError:
            return False
        return True
    return False


def main():
    argparser = ArgumentParser(description="Assign and verify UUIDs of Sigma rules")
    argparser.add_argument("--verify", "-V", action="store_true", help="Verify existence and uniqueness of UUID assignments. Exits with error code if verification fails.")
    argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose.")
    argparser.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories.")
    argparser.add_argument("--error", "-e", action="store_true", help="Exit with error code 10 on verification failures.")
    argparser.add_argument("inputs", nargs="+", help="Sigma rule files or repository directories")
    args = argparser.parse_args()

    if args.verbose:
        print_verbose()

    if args.recursive:
        paths = [ p for pathname in args.inputs for p in Path(pathname).glob("**/*") if p.is_file() ]
    else:
        paths = [ Path(pathname) for pathname in args.inputs ]

    uuids = set()
    passed = True
    for path in paths:
        print_verbose("Rule {}".format(str(path)))
        with path.open("r",encoding="UTF-8") as f:
            rules = list(ruamel.yaml.load_all(f,Loader=ruamel.yaml.RoundTripLoader))
        
        if args.verify:
            i = 0
            for rule in rules:
                if is_global(rule): # No id in global section
                    if 'id' in rule:
                        passed = False
                        print("Rule {} in file {} has ID in global section.".format(i,str(path)))
                else:
                    if not valid_id(rule,i,path):
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
        print("Please generate one with the sigma_uuid tool or here: https://www.uuidgenerator.net/version4")
        if args.error:
            exit(10)

if __name__ == "__main__":
    main()
