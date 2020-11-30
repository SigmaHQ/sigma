#!/usr/bin/env python3
# Merge a Sigma rule collection into full Sigma rules
# Copyright 2017 Thomas Patzke

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

import sys
import argparse
import yaml

from sigma.parser.collection import SigmaCollectionParser

def main():
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

if __name__ == "__main__":
    main()
