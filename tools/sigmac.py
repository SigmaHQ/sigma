#!/usr/bin/env python3
# A Sigma to SIEM converter

import sys
import argparse
import yaml
import json
import backends

def print_verbose(*args, **kwargs):
    if cmdargs.verbose or cmdargs.debug:
        print(*args, **kwargs)

def print_debug(*args, **kwargs):
    if cmdargs.debug:
        print(*args, **kwargs)

argparser = argparse.ArgumentParser(description="Convert Sigma rules into SIEM signatures.")
argparser.add_argument("--recurse", "-r", help="Recurse into subdirectories")
argparser.add_argument("--target", "-t", default="null", choices=backends.getBackendDict().keys(), help="Output target format")
argparser.add_argument("--target-list", "-l", action="store_true", help="List available output target formats")
argparser.add_argument("--output", "-o", help="Output file or filename prefix if multiple files are generated")
argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose")
argparser.add_argument("--debug", "-d", action="store_true", help="Debugging output")
argparser.add_argument("inputs", nargs="*", help="Sigma input files")
cmdargs = argparser.parse_args()

if cmdargs.target_list:
    for backend in backends.getBackendList():
        print("%10s: %s" % (backend.identifier, backend.__doc__))
    sys.exit(0)

for sigmafile in cmdargs.inputs:
    print_verbose("Processing Sigma input %s" % (sigmafile))
    try:
        f = open(sigmafile)
        parsedyaml = yaml.safe_load(f)
        print_debug(json.dumps(parsedyaml, indent=2))
    except OSError as e:
        print("Failed to open Sigma file %s: %s" % (sigmafile, str(e)))
    except yaml.parser.ParserError as e:
        print("Sigma file %s is no valid YAML: %s" % (sigmafile, str(e)))
    finally:
        f.close()
