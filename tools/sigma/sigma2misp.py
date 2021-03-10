#!/usr/bin/env python3
# Import given Sigma rules to MISP

import argparse
import pathlib
import urllib3
urllib3.disable_warnings()
from pymisp import PyMISP, MISPEvent

def create_new_event(args, misp):
    if hasattr(misp, "new_event"):
        return misp.new_event(info=args.info)["Event"]["id"]
    
    event = MISPEvent()
    event.info = args.info
    return misp.add_event(event)["Event"]["id"]


class MISPImportArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(
            description="Import Sigma rules into MISP events",
            epilog="Parameters can be read from a file by a @filename parameter. The file should contain one parameter per line. Dashes may be omitted.",
            fromfile_prefix_chars="@",
        )

    def convert_arg_line_to_args(self, line : str):
        return ("--" + line.lstrip("--")).split()

def main():
    argparser = MISPImportArgumentParser()
    argparser.add_argument("--url", "-u", default="https://localhost", help="URL of MISP instance")
    argparser.add_argument("--key", "-k", required=True, help="API key")
    argparser.add_argument("--insecure", "-I", action="store_false", help="Disable TLS certificate validation.")
    argparser.add_argument("--event", "-e", type=int, help="Add Sigma rule to event with this ID. If not set, create new event.")
    argparser.add_argument("--same-event", "-s", action="store_true", help="Import all Sigma rules to the same event, if no event is set.")
    argparser.add_argument("--info", "-i", default="Sigma import", help="Event Information field for newly created MISP event.")
    argparser.add_argument("--recursive", "-r", action="store_true", help="Recursive traversal of directory")
    argparser.add_argument("sigma", nargs="+", help="Sigma rule file that should be imported")
    args = argparser.parse_args()

    if args.recursive:
        paths = [ p for pathname in args.sigma for p in pathlib.Path(pathname).glob("**/*") if p.is_file() ]
    else:
        paths = [ pathlib.Path(sigma) for sigma in args.sigma ]

    misp = PyMISP(args.url, args.key, args.insecure)
    if args.event:
        if hasattr(misp, "get"):
            eventid = misp.get(args.event)["Event"]["id"]
        else:
            eventid = misp.get_event(args.event)["Event"]["id"]

    first = True

    for sigma in paths:
        if not args.event and (first or not args.same_event):
            eventid = create_new_event(args, misp)
        print("Importing Sigma rule {} into MISP event {}...".format(sigma, eventid, end=""))
        f = sigma.open("rt")

        if hasattr(misp, "add_named_attribute"):
            misp.add_named_attribute(eventid, "sigma", f.read())
        else:
            event = misp.get_event(eventid, pythonify=True)
            event.add_attribute("sigma", f.read())
            misp.update_event(event)

        f.close()
        first = False

if __name__ == "__main__":
    main()
