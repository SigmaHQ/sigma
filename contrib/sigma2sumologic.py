#!/usr/bin/python
# Copyright 2018 juju4

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
Project: sigma2sumologic.py
Date: 11 Jan 2019
Author: juju4
Version: 1.0
Description: This script executes sumologic search queries from Sigma SIEM rules.
Workflow:
    1. Convert rules with sigmac
    2. Enrich: add ignore+local custom rules, priority
    3. Format
    4. Get results and save to txt/xlsx files
Requirements:
    $ pip install sumologic-sdk pyyaml pandas
"""

import re
import os, sys, stat
import glob
import subprocess
import argparse
import yaml
import traceback
import logging
from sumologic import SumoLogic
import time
import datetime
import json
import pandas

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - p%(process)s {%(pathname)s:%(lineno)d} - %(levelname)s - %(message)s')
handler = logging.FileHandler('sigma2sumo.log')
handler.setFormatter(formatter)
logger.addHandler(handler)

parser = argparse.ArgumentParser(description='Execute sigma rules in sumologic')
parser.add_argument("--conf", help="script yaml config file", type=str, required=True)
parser.add_argument("--accessid", help="Sumologic Access ID", type=str, required=False)
parser.add_argument("--accesskey", help="Sumologic Access Key", type=str, required=False)
parser.add_argument("--endpoint", help="Sumologic url endpoint", type=str, required=False)
parser.add_argument("--ruledir", help="sigma rule directory path to convert", type=str, required=False)
parser.add_argument("--outdir", help="output directory to create rules", type=str, required=False)
parser.add_argument("--sigmac", help="Sigmac location", default="../tools/sigmac", type=str)
parser.add_argument("--realerttime", help="Realert time (optional value, default 5 minutes)", type=str, default=5)
parser.add_argument("--debug", help="Show debug output", type=bool, default=False)
args = parser.parse_args()

LIMIT = 100
delay = 5

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
        logger.debug("file_content: %s" % file_content)
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

def get_rule_as_sumologic(file):
    """
    Function used to get sumologic query output from rule file
    :type file: str
    :param file: rule filename
    :return: string query
    """
    if not os.path.exists(args.sigmac):
        logger.error("Cannot find sigmac rule coverter at '%s', please set a correct location via '--sigmac'")
    cmd = [args.sigmac, file, "--target", "sumologic"]
    logger.info('get_rule_as_sumologic cmd: %s' % cmd)
    process = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = process.communicate()

    # output is byte-string...
    output = output.decode("utf-8")
    err = err.decode("utf-8")

    logger.info('get_rule_as_sumologic output: %s' % output)
    logger.info('get_rule_as_sumologic stderr: %s' % err)
    if err or "unsupported" in err:
        logger.error('Unsupported output at this time')
        raise Exception('Unsupported output at this time')
    output = output.split("\n")
    # Remove empty string from \n
    output = [a for a in output if a]
    # Handle case of multiple queries returned
    if len(output) > 1:
        return " OR ".join(output)
    return "".join(output)

if args.help:
    parser_print_help()

if args.conf:
    with open(args.conf, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
    args.accessid = cfg['accessid']
    args.accesskey = cfg['accesskey']
    args.endpoint = cfg['endpoint']
    args.ruledir = cfg['ruledir']
    args.outdir = cfg['outdir']
    args.sigmac = cfg['sigmac']
    try:
        args.recursive = cfg['recursive']
    except:
        args.recursive = False
    if args.recursive:
        globpath = args.ruledir + "/**/*.yml"
    else:
        globpath = args.ruledir + "/*.yml"
    logger.debug("args: %s" % args)
    logger.debug("globpath: %s" % globpath)

if args.outdir and not os.path.isdir(args.outdir):
    os.mkdir(args.outdir, stat.S_IRWXU)

# recursive
for file in glob.iglob(globpath):
# non-recursive (above, not working...)
#for file in glob.iglob(args.ruledir + "/*.yml"):

    file_basename = os.path.basename(os.path.splitext(file)[0])
    file_basenamepath = os.path.splitext(file)[0]
    file_ext = os.path.splitext(file)[1]
    try:
        if file_ext != '.yml':
            continue

        logger.info("Processing %s ..." % file_basename)
        with open(file, "rb") as f:
            file_content = f.read()

        logger.info("Rule file: %s" % file)

        sumo_query = get_rule_as_sumologic(file)

        logger.info("  Checking if custom query file: %s" % file_basenamepath + '.custom')
        if os.path.isfile(file_basenamepath + '.custom'):
            # FIXME! want to add something in the middle for parsing for example...
            logger.info("  Adding custom part to end query from: %s" % file_basenamepath + '.custom')
            with open(file_basenamepath + '.custom', "rb") as f:
                sumo_query += " " + f.read().decode('utf-8')
        elif 'count ' not in sumo_query and ('EventID=' in sumo_query):
                sumo_query += " | count _sourceCategory, hostname, EventID, msg_summary, _raw"
        elif 'count ' not in sumo_query:
                sumo_query += " | count _sourceCategory, hostname, _raw"

        logger.info("Final sumo query: %s" % sumo_query)

    except Exception as e:
        if args.debug:
            traceback.print_exc()
        logger.exception("error generating sumo query " + str(file) + "----" + str(e))
        pass

    try:
        # Run query
        # https://github.com/SumoLogic/sumologic-python-sdk/blob/master/scripts/search-job.py
        sumo = SumoLogic(args.accessid, args.accesskey, args.endpoint)
        toTime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        fromTime = datetime.datetime.strptime(toTime, "%Y-%m-%dT%H:%M:%S") - datetime.timedelta(hours = 24)
        fromTime = fromTime.strftime("%Y-%m-%dT%H:%M:%S")
        timeZone = 'UTC'
        byReceiptTime = True

        sj = sumo.search_job(sumo_query, fromTime, toTime, timeZone, byReceiptTime)

        status = sumo.search_job_status(sj)
        while status['state'] != 'DONE GATHERING RESULTS':
            if status['state'] == 'CANCELLED':
                break
            time.sleep(delay)
            status = sumo.search_job_status(sj)

    except Exception as e:
        if args.debug:
            traceback.print_exc()
        logger.exception("error seaching sumo  " + str(file) + "----" + str(e))
        with open(os.path.join(args.outdir, "sigma-" + file_basename + '-error.txt'), "w") as f:
            f.write(json.dumps(r, indent=4, sort_keys=True) + " ERROR: %s\n\nQUERY: %s" % (e, sumo_query))
        pass

    logger.info("Sumo search job status: %s" % status['state'])

    try:
        if status['state'] == 'DONE GATHERING RESULTS':
            count = status['recordCount']
            limit = count if count < LIMIT and count != 0 else LIMIT # compensate bad limit check
            r = sumo.search_job_records(sj, limit=limit)
            logger.info("Sumo search results: %s" % r)

        logger.info("Saving final sumo query for %s to %s" % (file, os.path.join(args.outdir, "sigma-" + file_basename + '.sumo')))
        with open(os.path.join(args.outdir, "sigma-" + file_basename + '.sumo'), "w") as f:
            f.write(sumo_query)
        if r and r['records'] != []:
            logger.info("Saving results")
            # as json text file
            with open(os.path.join(args.outdir, "sigma-" + file_basename + '.txt'), "w") as f:
                f.write(json.dumps(r, indent=4, sort_keys=True))
            # as excel file
            df = pandas.io.json.json_normalize(r['records'])
            with pandas.ExcelWriter(os.path.join(args.outdir, "sigma-" + file_basename + ".xlsx")) as writer:
                df.to_excel(writer, 'data')
                pandas.DataFrame({'References': [
                    "timeframe: from %s to %s" % (fromTime, toTime),
                    "Sumo endpoint: %s" % args.endpoint,
                    "Sumo query: %s" % sumo_query
                    ]}).to_excel(writer, 'comments')

        # and do whatever you want, email alert, report, ticket...

    except Exception as e:
        if args.debug:
            traceback.print_exc()
        logger.exception("error saving results " + str(file) + "----" + str(e))
        pass
