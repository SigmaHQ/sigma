#!/usr/bin/env python3
# Convert Sigma rules with EventIDs to rules with generic log sources

from argparse import ArgumentParser
import yaml
import sys
from pathlib import Path
from sigma.output import SigmaYAMLDumper

class Output(object):
    """Output base class"""
    def write(self, *args, **kwargs):
        self.f.write(*args, **kwargs)

class SingleFileOutput(Output):
    """Output into single file with multiple YAML documents. Each input file is announced with comment."""
    def __init__(self, name):
        self.f = open(name, "x")
        self.path = None
        self.first = True

    def new_output(self, path):
        """Announce new Sigma rule as input and start new YAML document."""
        if self.path is None or self.path != path:
            if self.first:
                self.first = False
            else:
                self.f.write("---\n")
            self.path = path
            self.f.write("# Sigma rule: {}\n".format(path))

    def finish(self):
        self.f.close()

class StdoutOutput(SingleFileOutput):
    """Like SingleFileOutput, just for standard output"""
    def __init__(self):
        self.f = sys.stdout
        self.path = None
        self.first = True

    def finish(self):
        pass

class DirectoryOutput(Output):
    """Output each input file into a corresponding output file in target directory."""
    def __init__(self, dirpath):
        self.d = dirpath
        self.f = None
        self.path = None
        self.opened = None

    def new_output(self, path):
        if self.path is None or self.path != path:
            if self.f is not None:
                self.f.close()
            self.path = path
            self.opened = False     # opening file is deferred to first write

    def write(self, *args, **kwargs):
        if not self.opened:
            self.f = (self.d / self.path.name).open("x")
        super().write(*args, **kwargs)

    def finish(self):
        if self.f is not None:
            self.f.close()

def get_output(output):
    if output is None:
        return StdoutOutput()

    path = Path(output)
    if path.is_dir():
        return DirectoryOutput(path)
    else:
        return SingleFileOutput(output)

class AmbiguousRuleException(TypeError):
    def __init__(self, ids):
        super().__init__()
        self.ids = ids

    def __str__(self):
        return(", ".join([str(eid) for eid in self.ids]))

def convert_to_generic(yamldoc):
    changed = False
    try:
        product = yamldoc["logsource"]["product"]
        service = yamldoc["logsource"]["service"]
    except KeyError:
        return False

    if product == "windows" and service in ("sysmon", "security"):
        # Currently, only Windows Security or Sysmon are relevant
        eventids = set()
        for name, detection in yamldoc["detection"].items():      # first collect all event ids
            if name == "condition" or type(detection) is not dict:
                continue

            try:
                eventid = detection["EventID"]
                try:    # expect that EventID attribute contains a list
                    eventids.update(eventid)
                except TypeError:   # if this fails, it's a plain value
                    eventids.add(eventid)
            except KeyError:    # No EventID attribute
                pass

        if 1 in eventids and service == "sysmon" or \
                4688 in eventids and service == "security":
            if len(eventids) == 1:      # only convert if one EventID collected, else it gets complicated
                # remove all EventID definitions
                empty_name = list()
                for name, detection in yamldoc["detection"].items():
                    if name == "condition" or type(detection) is not dict:
                        continue
                    try:
                        del detection["EventID"]
                    except KeyError:
                        pass

                    if detection == {}:     # detection was reduced to nothing - remove it later
                        empty_name.append(name)

                for name in empty_name:     # delete empty detections
                    del yamldoc["detection"][name]

                if yamldoc["detection"] == {}:  # delete detection section if empty
                    del yamldoc["detection"]

                # rewrite log source
                yamldoc["logsource"] = {
                        "category": "process_creation",
                        "product":  "windows"
                        }

                changed = True
            else:                       # raise an exception to print a warning message to make user aware about the issue
                raise AmbiguousRuleException(eventids)
    return changed

def get_input_paths(args):
    if args.recursive:
        return [ p for pathname in args.sigma for p in Path(pathname).glob("**/*") if p.is_file() ]
    else:
        return [ Path(sigma) for sigma in args.sigma ]

argparser = ArgumentParser(description="Convert between classical and generic log source Sigma rules.")
argparser.add_argument("--output", "-o", help="Output file or directory. Default: standard output.")
argparser.add_argument("--recursive", "-r", action="store_true", help="Recursive traversal of directory")
argparser.add_argument("--converted-list", "-c", help="Write list of rule files that were successfully converted (default: stdout)")
argparser.add_argument("sigma", nargs="+", help="Sigma rule file(s) that should be converted")
args = argparser.parse_args()

# Define order-preserving representer from dicts/maps
def yaml_preserve_order(self, dict_data):
    return self.represent_mapping("tag:yaml.org,2002:map", dict_data.items())

yaml.add_representer(dict, yaml_preserve_order)

input_paths = get_input_paths(args)
output = get_output(args.output)
if args.converted_list:
    fconv = open(args.converted_list, "w")
else:
    fconv = sys.stdout

for path in input_paths:
    try:
        f = path.open("r")
    except OSError as e:
        print("Error while reading Sigma rule {}: {}".format(path, str(e)), file=sys.stderr)
        sys.exit(1)

    try:
        yamldocs = list(yaml.safe_load_all(f))
    except yaml.YAMLError as e:
        print("YAML parse error while parsing Sigma rule {}: {}".format(path, str(e)), file=sys.stderr)
        sys.exit(2)

    yamldoc_num = 0
    changed = False
    for yamldoc in yamldocs:
        yamldoc_num += 1
        output.new_output(path)
        try:
            changed |= convert_to_generic(yamldoc)
        except AmbiguousRuleException as e:
            changed = False
            print("Rule {} in file {} contains multiple EventIDs: {}".format(yamldoc_num, str(path), str(e)), file=sys.stderr)

    yamldocs_idx = list(zip(range(len(yamldocs)), yamldocs))
    delete = set()
    for i, yamldoc_a in yamldocs_idx:     # iterate over all yaml document pairs
        for j, yamldoc_b in yamldocs_idx:
            if j <= i:      # symmetric relation, skip same comparisons
                continue
            if yamldoc_a == yamldoc_b:
                delete.add(j)

    for i in reversed(sorted(delete)):  # delete double yaml documents
        del yamldocs[i]

    # Common special case: two yaml docs, one global and one remainder of multiple following docs - merge them
    try:
        if len(yamldocs) == 2 and \
                yamldocs[0]["action"] == "global" and \
                "action" not in yamldocs[1] and \
                set(yamldocs[0].keys()) & set(yamldocs[1].keys()) == set():   # last condition: no common keys
            yamldocs[0].update(yamldocs[1])
            del yamldocs[1]
    except KeyError:
        pass

    if changed:     # only write output if changed
        try:
            output.write(yaml.dump_all(yamldocs, Dumper=SigmaYAMLDumper, indent=4, width=160, default_flow_style=False))
            print(path, file=fconv)
        except OSError as e:
            print("Error while writing result: {}".format(str(e)), file=sys.stderr)
            sys.exit(2)

output.finish()
