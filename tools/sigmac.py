#!/usr/bin/env python3
# A Sigma to SIEM converter

import sys
import argparse
import yaml
import json
from sigma import SigmaParser, SigmaParseError
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
argparser.add_argument("--config", "-c", help="Configuration mit field name and index mapping for target environment")
argparser.add_argument("--output", "-o", help="Output file or filename prefix if multiple files are generated")
argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose")
argparser.add_argument("--debug", "-d", action="store_true", help="Debugging output")
argparser.add_argument("inputs", nargs="*", help="Sigma input files")
cmdargs = argparser.parse_args()

if cmdargs.target_list:
    for backend in backends.getBackendList():
        print("%10s: %s" % (backend.identifier, backend.__doc__))
    sys.exit(0)

try:
    backend = backends.getBackend(cmdargs.target)()
except LookupError as e:
    print("Backend not found!")
    sys.exit(1)

for sigmafile in cmdargs.inputs:
    print_verbose("* Processing Sigma input %s" % (sigmafile))
    try:
        f = open(sigmafile)
        parser = SigmaParser(f)
        print_debug("Parsed YAML:\n", json.dumps(parser.parsedyaml, indent=2))
        parser.parse_sigma()
        for condtoken in parser.condtoken:
            print_debug("Condition Tokens:", condtoken)
        for condparsed in parser.condparsed:
            print_debug("Condition Parse Tree:", condparsed)
            print(backend.generate(condparsed))
    except OSError as e:
        print("Failed to open Sigma file %s: %s" % (sigmafile, str(e)))
    except yaml.parser.ParserError as e:
        print("Sigma file %s is no valid YAML: %s" % (sigmafile, str(e)))
    except SigmaParseError as e:
        print("Sigma parse error in %s: %s" % (sigmafile, str(e)))
    except NotImplementedError as e:
        print("An unsupported feature is required for this Sigma rule: " + str(e))
        print("Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma")
    finally:
        f.close()
        print_debug()
