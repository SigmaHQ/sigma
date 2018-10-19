#!/usr/bin/env python3
# Import given Sigma rules to MISP

import argparse
import urllib3
urllib3.disable_warnings()
from pymisp import PyMISP

def create_new_event():
    return misp.new_event(info=args.info)["Event"]["id"]

class MISPImportArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(
            description="Import Sigma rules into MISP events",
            epilog="Parameters can be read from a file by a @filename parameter. The file should contain one parameter per line. Dashes may be omitted.",
            fromfile_prefix_chars="@",
        )

    def convert_arg_line_to_args(self, line : str):
        return ("--" + line.lstrip("--")).split()

argparser = MISPImportArgumentParser()
argparser.add_argument("--url", "-u", default="https://localhost", help="URL of MISP instance")
argparser.add_argument("--key", "-k", required=True, help="API key")
argparser.add_argument("--insecure", "-I", action="store_false", help="Disable TLS certifcate validation.")
argparser.add_argument("--event", "-e", type=int, help="Add Sigma rule to event with this ID. If not set, create new event.")
argparser.add_argument("--same-event", "-s", action="store_true", help="Import all Sigma rules to the same event, if no event is set.")
argparser.add_argument("--info", "-i", default="Sigma import", help="Event Information field for newly created MISP event.")
argparser.add_argument("sigma", nargs="+", help="Sigma rule file that should be imported")
args = argparser.parse_args()

misp = PyMISP(args.url, args.key, args.insecure)
if args.event:
    eventid = misp.get(args.event)["Event"]["id"]

first = True
for sigma in args.sigma:
    if not args.event and (first or not args.same_event):
        eventid = create_new_event()
    print("Importing Sigma rule {} into MISP event {}...".format(sigma, eventid, end=""))
    f = open(sigma, "rt")
    misp.add_named_attribute(eventid, "sigma", f.read())
    f.close()
    first = False
