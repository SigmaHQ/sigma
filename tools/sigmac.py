#!/usr/bin/env python3
# A Sigma to SIEM converter

import sys
import argparse
import yaml
import json
import pathlib
import itertools
import logging
from sigma import SigmaCollectionParser, SigmaCollectionParseError, SigmaParseError, SigmaConfiguration, SigmaConfigParseError, SigmaRuleFilter, SigmaRuleFilterParseException
import backends

logger = logging.getLogger(__name__)

def print_verbose(*args, **kwargs):
    if cmdargs.verbose or cmdargs.debug:
        print(*args, **kwargs)

def print_debug(*args, **kwargs):
    if cmdargs.debug:
        print(*args, **kwargs)

def alliter(path):
    for sub in path.iterdir():
        if sub.is_dir():
            yield from alliter(sub)
        else:
            yield sub

def get_inputs(paths, recursive):
    if recursive:
        return list(itertools.chain.from_iterable([list(alliter(pathlib.Path(p))) for p in paths]))
    else:
        return [pathlib.Path(p) for p in paths]

argparser = argparse.ArgumentParser(description="Convert Sigma rules into SIEM signatures.")
argparser.add_argument("--recurse", "-r", action="store_true", help="Recurse into subdirectories (not yet implemented)")
argparser.add_argument("--filter", "-f", help="""
Define comma-separated filters that must match (AND-linked) to rule to be processed.
Valid filters: level<=x, level>=x, level=x, status=y, logsource=z.
x is one of: low, medium, high, critical.
y is one of: experimental, testing, stable.
z is a word appearing in an arbitrary log source attribute.
Multiple log source specifications are AND linked.
        """)
argparser.add_argument("--target", "-t", default="es-qs", choices=backends.getBackendDict().keys(), help="Output target format")
argparser.add_argument("--target-list", "-l", action="store_true", help="List available output target formats")
argparser.add_argument("--config", "-c", help="Configuration with field name and index mapping for target environment (not yet implemented)")
argparser.add_argument("--output", "-o", default=None, help="Output file or filename prefix if multiple files are generated (not yet implemented)")
argparser.add_argument("--backend-option", "-O", action="append", help="Options and switches that are passed to the backend")
argparser.add_argument("--defer-abort", "-d", action="store_true", help="Don't abort on parse or conversion errors, proceed with next rule. The exit code from the last error is returned")
argparser.add_argument("--ignore-not-implemented", "-I", action="store_true", help="Only return error codes for parse errors and ignore errors for rules with not implemented features")
argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose")
argparser.add_argument("--debug", "-D", action="store_true", help="Debugging output")
argparser.add_argument("inputs", nargs="*", help="Sigma input files")
cmdargs = argparser.parse_args()

if cmdargs.debug:
    logger.setLevel(logging.DEBUG)

if cmdargs.target_list:
    for backend in backends.getBackendList():
        print("%10s: %s" % (backend.identifier, backend.__doc__))
    sys.exit(0)

rulefilter = None
if cmdargs.filter:
    try:
        rulefilter = SigmaRuleFilter(cmdargs.filter)
    except SigmaRuleFilterParseException as e:
        print("Parse error in Sigma rule filter expression: %s" % str(e), file=sys.stderr)
        sys.exit(9)

out = sys.stdout
sigmaconfig = SigmaConfiguration()
if cmdargs.config:
    try:
        conffile = cmdargs.config
        f = open(conffile)
        sigmaconfig = SigmaConfiguration(f)
    except OSError as e:
        print("Failed to open Sigma configuration file %s: %s" % (conffile, str(e)), file=sys.stderr)
        exit(5)
    except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
        print("Sigma configuration file %s is no valid YAML: %s" % (conffile, str(e)), file=sys.stderr)
        exit(6)
    except SigmaConfigParseError as e:
        print("Sigma configuration parse error in %s: %s" % (conffile, str(e)), file=sys.stderr)
        exit(7)

backend_options = backends.BackendOptions(cmdargs.backend_option)

try:
    backend = backends.getBackend(cmdargs.target)(sigmaconfig, backend_options, cmdargs.output)
    # not existing backend is already detected by argument parser
except IOError as e:
    print("Failed to open output file '%s': %s" % (cmdargs.output, str(e)), file=sys.stderr)
    exit(1)

error = 0
for sigmafile in get_inputs(cmdargs.inputs, cmdargs.recurse):
    print_verbose("* Processing Sigma input %s" % (sigmafile))
    try:
        f = sigmafile.open()
        parser = SigmaCollectionParser(f, sigmaconfig, rulefilter)
        parser.generate(backend)
    except OSError as e:
        print("Failed to open Sigma file %s: %s" % (sigmafile, str(e)), file=sys.stderr)
        error = 5
    except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
        print("Sigma file %s is no valid YAML: %s" % (sigmafile, str(e)), file=sys.stderr)
        error = 3
        if not cmdargs.defer_abort:
            sys.exit(error)
    except (SigmaParseError, SigmaCollectionParseError) as e:
        print("Sigma parse error in %s: %s" % (sigmafile, str(e)), file=sys.stderr)
        error = 4
        if not cmdargs.defer_abort:
            sys.exit(error)
    except backends.BackendError as e:
        print("Backend error in %s: %s" % (sigmafile, str(e)), file=sys.stderr)
        error = 8
        if not cmdargs.defer_abort:
            sys.exit(error)
    except NotImplementedError as e:
        print("An unsupported feature is required for this Sigma rule: " + str(e), file=sys.stderr)
        print("Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma", file=sys.stderr)
        if not cmdargs.ignore_not_implemented:
            error = 42
            if not cmdargs.defer_abort:
                sys.exit(error)
    finally:
        try:
            f.close()
        except:
            pass
backend.finalize()

sys.exit(error)
