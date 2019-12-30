#!/usr/bin/python
# Copyright 2018 David Routin

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
"""
Project: sigma2elastalert.py
Date: 25 Feb 2018
Author: David ROUTIN  (@Rewt_1)
Version: 1.0
Description: This script creates elastalert configuration files from Sigma SIEM rules.
"""

import re
import os
import glob
import subprocess
import argparse
import yaml
import traceback

parser = argparse.ArgumentParser()
parser.add_argument("--eshost", help="Elasticsearch host", type=str, required=True)
parser.add_argument("--esport", help="Elasticsearch port", type=str, required=True)
parser.add_argument("--ruledir", help="sigma rule directory path to convert", type=str, required=True)
parser.add_argument("--index", help="Elasticsearch index name egs: \"winlogbeat-*\"", type=str, required=True)
parser.add_argument("--email", help="email address to send mail alert", type=str, required=True)
parser.add_argument("--outdir", help="output directory to create elastalert rules", type=str, required=True)
parser.add_argument("--sigmac", help="Sigmac location", default="../tools/sigmac", type=str)
parser.add_argument("--realerttime", help="Realert time (optional value, default 5 minutes)", type=str, default=5)
parser.add_argument("--debug", help="Show debug output", type=bool, default=False)
args = parser.parse_args()

custom_query_keys = ["sensor", "Hostname", "EventID", "src_ip", "dst_ip"]


template="""es_host: ESHOST
es_port: ESPORT
name: "TITLE"
description: "DESCRIPTION"
index: INDEX
filter:
- query:
    query_string:
      query: 'QUERY'
realert:
 minutes: MINUTES
query_key: UNIQKEYS
type: any
include: UNIQKEYS
alert:
- "email"

# (required, email specific)
# a list of email addresses to send alerts to
email:
- "EMAIL"
"""

def return_json_obj(x,custom_query_keys):
    """
    Function used to filter all ES query object as unique value including predefined list from custom_query_keys
    :param x: must contains ES query output
    :param custom_query_keys: takes the list of predefined element to match in document
    :return: a clean list (set) of all the query keys (EventID,TargetUserName...)
    """
    # type: (str, list) -> list
    y = x.replace(" ", "\n").split()
    out = set()
    for i in y:
        out.update(re.findall("([a-zA-Z]+)\:", i))

    for qk in custom_query_keys:
        try:
            out.remove(qk)
        except:
            pass
    out = list(out)
    count = 0
    for qk in custom_query_keys:
        count += 1
        out.insert(count-1, qk)
    return out

def rule_element(file_content, elements):
    """
    Function used to get specific element from yaml document and return content
    :type file_content: str
    :type elements: list
    :param file_content:
    :param elements: list of elements of the yaml document to get "title", "description"
    :return: the value of the key in the yaml document
    """
    try:
        yaml.safe_load(file_content.replace("---",""))
    except:
        raise Exception('Unsupported')
    element_output = ""
    for e in elements:
        try:
            element_output = yaml.safe_load(file_content.replace("---",""))[e]
        except:
            pass
    if element_output is None:
        return ""
    return element_output

def get_rule_as_esqs(file):
    """
    Function used to get Elastic query output from rule fome
    :type file: str
    :param file: rule filename
    :return: string es query
    """
    if not os.path.exists(args.sigmac):
        print("Cannot find sigmac rule coverter at '%s', please set a correct location via '--sigmac'")
    cmd = [args.sigmac, file, "--target", "es-qs"]
    output = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()
    if "unsupported" in output:
        raise Exception('Unsupported output at this time')
    output = output.split("\n")
    # Remove empty string from \n
    output = [a for a in output if a]
    # Handle case of multiple queries returned
    if len(output) > 1:
        return " OR ".join(output)
    return "".join(output)

# Dictionary that contains args set at launch time
convert_args = {
    "ESHOST": args.eshost,
    "ESPORT": args.esport,
    "INDEX": args.index,
    "EMAIL": args.email,
    "MINUTES": args.realerttime
}

for file in glob.glob(args.ruledir + "/*"):
    output_elast_config = template
    try:
        print("Processing %s ..." % file)
        with open(file, "rb") as f:
            file_content = f.read()

        # Dictionary that contains args with values returned by functions
        translate_func = {'QUERY': get_rule_as_esqs(file),
                        'TITLE': rule_element(file_content, ["title", "name"]),
                        'DESCRIPTION': rule_element(file_content, ["description"]),
                        'UNIQKEYS': str(return_json_obj(get_rule_as_esqs(file), custom_query_keys))
                        }
        for entry in convert_args:
            output_elast_config = re.sub(entry, str(convert_args[entry]), output_elast_config)
        for entry in translate_func:
            output_elast_config = re.sub(entry, translate_func[entry], output_elast_config)
        print("Converting file " + file)
        with open(os.path.join(args.outdir, "sigma-" + file.split("/")[-1]), "w") as f:
                f.write(output_elast_config)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        print("error " + str(file) + "----" + str(e))
        pass

