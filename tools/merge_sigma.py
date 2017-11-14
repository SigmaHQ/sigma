#!/usr/bin/env python3
# Merge a Sigma rule collection into full Sigma rules

import sys
import argparse
import yaml

from sigma import SigmaCollectionParser

argparser = argparse.ArgumentParser(description="Convert Sigma rules into SIEM signatures.")
argparser.add_argument("input", help="Sigma input file")
cmdargs = argparser.parse_args()

try:
    f = open(cmdargs.input, "r")
except IOError as e:
    print("Error while opening input file: %s" % str(e), file=sys.stderr)
    sys.exit(1)

content = "".join(f.readlines())
f.close()
sc = SigmaCollectionParser(content)

print(yaml.dump_all(sc, default_flow_style=False))
