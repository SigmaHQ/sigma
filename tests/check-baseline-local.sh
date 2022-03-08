#!/bin/bash

if [[ -z $(command -v jq) ]]; then
    >2& echo "jq not found. Please install."
    >2& echo "Exiting"
    exit 1
fi

if [[ -z $(command -v wget) ]]; then
    >2& echo "wget not found. Please install."
    >2& echo "Exiting"
    exit 1
fi

if [[ -z $(command -v realpath) ]]; then
    >2& echo "realpath not found. Please install coreutils."
    >2& echo "Exiting"
    exit 1
fi

OS=$(uname -s)

if [[ "${OS}" != "Linux" && "${OS}" != "Darwin" ]]; then
    >2& echo "This script only supports Linux and MacOS"
    >2& echo "$(uname -s) is not a supported OS"
    >2& echo "Exiting"
    exit 1
fi

SCRIPT="$(realpath $0)"
TOOLS="${SCRIPT%/*}"
SIGMA="${TOOLS%/*}"

if [[ -n "$1" && -d "$1" && -r "$1" ]]; then
    RULES="$1"
else
    RULES="${SIGMA}"/rules
fi

TMP=$(mktemp -d)
if [[ -z "${TMP}" || ! -d "${TMP}" || ! -w "${TMP}" ]]; then
    >2& echo "Error: Created temporary directory ${TMP} is not writable."
    >2& echo "Exiting"
    exit 1
fi


cd "${TMP}"

echo
echo "Copy rules from ${SIGMA} to ${TMP}"
cp -r "${RULES}"/windows .
echo
echo "Download evtx-sigma-checker"
if [[ "${OS}" == "Linux" ]]; then
    wget --no-verbose --progress=bar --show-progress https://github.com/NextronSystems/evtx-baseline/releases/latest/download/evtx-sigma-checker
elif [[ "${OS}" == "Darwin" ]]; then
    wget --no-verbose --progress=bar --show-progress https://github.com/NextronSystems/evtx-baseline/releases/latest/download/evtx-sigma-checker-darwin -O evtx-sigma-checker
fi
echo
echo "Download and extract Windows 10 baseline events"
wget --no-verbose --progress=bar --show-progress https://github.com/NextronSystems/evtx-baseline/releases/latest/download/win10-client.tgz
tar xzf win10-client.tgz
echo
echo "Remove deprecated rules"
grep -ERl "^status: deprecated" windows | xargs -r rm -v
echo
echo "Check for Sigma matches in baseline (this takes at least 2 minutes)"
chmod +x evtx-sigma-checker
./evtx-sigma-checker --log-source "${SIGMA}"/tools/config/thor.yml --evtx-path Logs_Client/ --rule-path windows/ > findings.json

echo
echo "Checking for matches:"
"${SIGMA}"/.github/workflows/matchgrep.sh findings.json "${SIGMA}"/.github/workflows/known-FPs.csv

echo
read -p  "Removing temporary directory ${TMP}. Press Enter to continue." -s
echo
rm -r "${TMP}"
echo "Removed ${TMP}"
echo "Finished"
