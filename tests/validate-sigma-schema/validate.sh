#!/bin/bash

# Check if the check-jsonschema tool is installed
if ! command -v check-jsonschema &>/dev/null; then
    echo "check-jsonschema could not be found"
    echo "Please install it from PyPI using:"
    echo "pip install check-jsonschema"
    exit 1
fi

# Set the GITHUB_WORKSPACE environment variable to the current directory if it is not set
if [ -z "${GITHUB_WORKSPACE}" ]; then
    GITHUB_WORKSPACE="./"
fi

# for every newline-separated path in SIGMA_RULES_PATH, remove the newline and replace it with a space. Also remove any leading or trailing whitespace and remove ./ and // from the path
if [ -n "${SIGMA_RULES_PATH}" ]; then
    SIGMA_RULES_PATH=$(echo ${SIGMA_RULES_PATH} | sed 's/\\n/ /g' | sed 's/\/\/$/\//g' | sed 's/\.\/\.\//\.\//g' | awk '{$1=$1};1')
fi

# Convert newline-separated paths to space-separated paths
if [ -n "${SIGMA_RULES_PATH}" ]; then
    # Get Sigma rules from the user-specified path
    PATHS=$(echo ${SIGMA_RULES_PATH} | awk -v ghws="${GITHUB_WORKSPACE}" '{print ghws$0}' | sed 's/\.\/\.\//\.\//g' | awk '{$1=$1};1')
    FILES=$(find ${PATHS} -type f -name "*.yml")
fi

if [ -z "${FILES}" ]; then
    echo "No Sigma rules found, please set the SIGMA_RULES_PATH environment variable"
    exit 1
fi

# If we are not running in a GitHub Action, set the default path to the repo root
if [ -z "${GITHUB_ACTION_PATH}" ]; then
    GITHUB_ACTION_PATH=${GITHUB_WORKSPACE}
fi

if [ ! ${SIGMA_SCHEMA_URL} == "" ] && [ ! ${SIGMA_SCHEMA_FILE} == "" ]; then
    echo "Both SIGMA_SCHEMA_URL and SIGMA_SCHEMA_FILE are set"
    echo "Please only set one of these environment variables"
    exit 1
fi

# Local schema file is preferred over the URL
if [ ! ${SIGMA_SCHEMA_FILE} == "" ]; then
    echo "Using the local sigma-schema.json"
    if [ ! -f "${GITHUB_ACTION_PATH}/sigma-schema.json" ]; then
        echo "The local sigma-schema.json does not exist."
        echo "Please download it from ${SIGMA_SCHEMA_URL}"
        echo "and place it in the ${GITHUB_ACTION_PATH} directory"
        exit 1
    fi
else
    # Set the SIGMA_SCHEMA_URL environment variable to the default Sigma schema path if it is not set
    if [ -z "${SIGMA_SCHEMA_URL}" ]; then
        SIGMA_SCHEMA_URL="https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/sigma-schema.json"
    fi
    echo "Downloading the latest version of the sigma-schema.json"
    wget ${SIGMA_SCHEMA_URL} -O ${GITHUB_ACTION_PATH}/sigma-schema.json
fi

echo "Validating Sigma rules against sigma-schema.json"
check-jsonschema --schemafile ${GITHUB_ACTION_PATH}/sigma-schema.json ${FILES}
