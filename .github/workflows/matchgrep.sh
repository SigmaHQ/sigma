#!/bin/bash

infile=$1
fps=$2

if [[ -z ${infile} || -z ${fps} ]]; then
    >&2 echo "usage: $0 [json-file] [FPs.csv]" 
    exit 1
fi

if [[ ! -f ${infile}  || ! -r ${infile} ]]; then
    >&2 echo "${infile} is not a valid, readable file"
    exit 2
fi
if [[ ! -f ${fps}  || ! -r ${fps} ]]; then
    >&2 echo "${fps} is not a valid, readable file"
    exit 2
fi

# Exclude all rules with level "low"
findings=$(grep -v '"RuleLevel":"low"' ${infile})

{
    read # Skip CSV header
    while IFS=\; read -r id name fpstring; do
        findings=$(echo "${findings}" | grep -iEv "\"RuleId\":\"${id}\".*${fpstring}")
    done
} < ${fps}

if [[ -z ${findings} ]]; then
    echo "No matches found."
else
    >&2 echo "Found matches:"
    echo "${findings}"
    >&2 echo
    >&2 echo "Match overview:"
    echo ${findings} | jq -c '. | {RuleId, RuleTitle, RuleLevel}' | sort | uniq -c | sort -nr >&2
    >&2 echo
    >&2 echo "You either need to tune your rule(s) for false positives or add a false positive filter to .github/workflows/known-FPs.csv"
    exit 3
fi
