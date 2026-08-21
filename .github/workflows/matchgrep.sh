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
mismatch_rows=()
deprecated_rows=()
notfound_rows=()
{
    read -r # Skip CSV header
    while IFS=\; read -r id name _fpstring; do
        rulefile=$(grep -irl "^id: ${id}$" rules/ rules-emerging-threats/ rules-threat-hunting/ 2>/dev/null | head -1)
        if [[ -n "${rulefile}" ]]; then
            title=$(grep "^title:" "${rulefile}" | sed 's/^title: //')
            if [[ "${title}" != "${name}" ]]; then
                mismatch_rows+=("${id}|${name}|${title}")
            fi
        elif grep -irl "^id: ${id}$" deprecated/ 2>/dev/null | head -1 | grep -q .; then
            deprecated_rows+=("${id}|${name}")
        else
            notfound_rows+=("${id}|${name}")
        fi
    done
} < "${fps}"

validation_failed=0

if [[ ${#mismatch_rows[@]} -gt 0 ]]; then
    >&2 echo "Rule name mismatches — update the CSV Name to match the Rule Title:"
    { echo "RuleId|Name in known-FPs.csv|Title in Rule File"; printf '%s\n' "${mismatch_rows[@]}"; } | column -t -s'|' >&2
    >&2 echo
    validation_failed=1
fi

if [[ ${#deprecated_rows[@]} -gt 0 ]]; then
    >&2 echo "Deprecated rules — remove these entries from known-FPs.csv:"
    { echo "RuleId|Name in known-FPs.csv"; printf '%s\n' "${deprecated_rows[@]}"; } | column -t -s'|' >&2
    >&2 echo
    validation_failed=1
fi

if [[ ${#notfound_rows[@]} -gt 0 ]]; then
    >&2 echo "Unknown rule IDs — not found in any rule directory:"
    { echo "RuleId|Name in known-FPs.csv"; printf '%s\n' "${notfound_rows[@]}"; } | column -t -s'|' >&2
    >&2 echo
    validation_failed=1
fi

if [[ ${validation_failed} -ne 0 ]]; then
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
