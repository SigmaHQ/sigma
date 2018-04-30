#!/usr/bin/env python3
# CI Test script: generate all queries with es-qs backend and test them against local ES instance.
# Copyright 2018 Thomas Patzke

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

import asyncio
import functools
import sys
import pprint
import elasticsearch
import elasticsearch_async
pp = pprint.PrettyPrinter()

# Configuration
eshost = "localhost:9200"
index = "test"
sigmac_cmd = "tools/sigmac"
sigmac_processing_prefix = "* Processing Sigma input "

es = elasticsearch.Elasticsearch(hosts=[eshost])
esa = elasticsearch_async.AsyncElasticsearch(hosts=[eshost])

# Create empty test index
try:
    es.indices.create(index)
except elasticsearch.exceptions.RequestError as e:
    if e.error != 'resource_already_exists_exception':  # accept already existing index with same name
        raise e

queries = asyncio.Queue()

# sigmac runner coroutinne
async def run_sigmac():
    sigmac = asyncio.create_subprocess_exec(
            sigmac_cmd, "-t", "es-qs", "-v", "-I", "-r", "rules/",
            stdout=asyncio.subprocess.PIPE,
            )
    print("* Launching sigmac")
    proc = await sigmac
    print("* sigmac launched with PID {}".format(proc.pid))

    cur_rule = None
    while True:
        line = await proc.stdout.readline()
        if not line:
            print("* sigmac finished")
            await queries.put((None, None))
            break
        else:
            strline = str(line, 'utf-8').rstrip()
            if strline.startswith(sigmac_processing_prefix):
                cur_rule = strline[len(sigmac_processing_prefix):]
            else:
                await queries.put((cur_rule, strline))
    await proc.wait()

    exitcode = proc.returncode
    print("* sigmac returned with exit code {}".format(exitcode))
    return exitcode

# Generated query checker loop
async def check_queries():
    failed = list()
    print("# Waiting for queries")
    while True:
        rule, query = await queries.get()
        if query is not None:
            print("# Checking query (rule {}): {}".format(rule, query))
            result = await esa.indices.validate_query(index=index, q=query)
            valid = result['valid']

            print("# Received Result for rule {} query={}: {}".format(rule, query, valid))
            if not valid:
                try:
                    detail_result = await esa.search(index=index, q=query)
                except Exception as e:
                    error = e.info

                failed.append((rule, query, error))
            queries.task_done()
        else:
            queries.task_done()
            break
    print("# Finished query checks")

    return failed

task_check_query = asyncio.ensure_future(check_queries())
task_sigmac = asyncio.ensure_future(run_sigmac())
tasks = [
        task_check_query,
        task_sigmac
        ]

loop = asyncio.get_event_loop()
done, pending = loop.run_until_complete(asyncio.wait(tasks))
loop.close()
esa.transport.close()
print()

# Check if sigmac runned successfully
try:
    if task_sigmac.result() != 0:       # sigmac failed
        print("!!! sigmac failed while test!")
        sys.exit(1)
except Exception:
    print("!!! sigmac failed while test!")
    sys.exit(2)

# Check if query checks failed
try:
    query_check_result = task_check_query.result()
except Exception:
    print("!!! Query check failed!")
    sys.exit(3)

query_check_result_cnt = len(query_check_result)
if query_check_result_cnt > 0:
    print("!!! {} queries failed to check:".format(query_check_result_cnt))
    for rule, query, error in query_check_result:
        print("- {}: {}".format(rule, query))
        print("Error:")
        pp.pprint(error)
        print()
    sys.exit(4)
else:
    print("All query checks passed!")
