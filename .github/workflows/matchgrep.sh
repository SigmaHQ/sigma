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

# Validate that each RuleId in the CSV has a matching primary rule file with the same title
validation_errors=0
{
    read -r # Skip CSV header
    while IFS=\; read -r id name _fpstring; do
        rulefile=$(grep -irl "^id: ${id}$" rules/ rules-emerging-threats/ rules-threat-hunting/ 2>/dev/null | head -1)
        if [[ -n "${rulefile}" ]]; then
            title=$(grep "^title:" "${rulefile}" | sed 's/^title: //')
            if [[ "${title}" != "${name}" ]]; then
                >&2 echo "ERROR: Rule name mismatch in known-FPs.csv for ${id}:"
                >&2 echo "  Current  : '${name}'"
                >&2 echo "  Expected : '${title}' (${rulefile})"
                validation_errors=1
            fi
        elif grep -irl "^id: ${id}$" deprecated/ 2>/dev/null | head -1 | grep -q .; then
            >&2 echo "ERROR: Rule ${id} (CSV name: '${name}') is deprecated — remove it from known-FPs.csv"
            validation_errors=1
        else
            >&2 echo "ERROR: Rule ID not found in rules for ${id} (CSV name: '${name}')"
            validation_errors=1
        fi
    done
} < "${fps}"

if [[ ${validation_errors} -ne 0 ]]; then
    >&2 echo
    >&2 echo "Fix the RuleName column in .github/workflows/known-FPs.csv to match the rule titles above."
    exit 4
fi

# Exclude all rules with level "low"
findings=$(grep -v '"RuleLevel":"low"' "${infile}")

{
    read -r # Skip CSV header
    while IFS=\; read -r id _name fpstring; do
        findings=$(echo "${findings}" | grep -iEv "\"RuleId\":\"${id}\".*${fpstring}")
    done
} < "${fps}"

if [[ -z ${findings} ]]; then
    echo "No matches found."
else
    >&2 echo "Found matches:"
    echo "${findings}"
    >&2 echo
    >&2 echo "Match overview:"
    echo "${findings}" | jq -c '. | {RuleId, RuleTitle, RuleLevel}' | sort | uniq -c | sort -nr >&2
    >&2 echo
    >&2 echo "You either need to tune your rule(s) for false positives or add a false positive filter to .github/workflows/known-FPs.csv"
    exit 3
fi
