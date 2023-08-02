#!/bin/bash

# Check if the check-jsonschema tool is installed
if ! command -v check-jsonschema &> /dev/null
then
    echo "check-jsonschema could not be found"
    echo "Please install it from PyPI using:"
    echo "pip install check-jsonschema"
    exit
fi

# Validate all the Sigma rules in the current directory
echo "Validating Sigma rules against schema.json"
check-jsonschema --schemafile sigma-schema.json $(find ./rules ./rules-compliance ./rules-dfir ./rules-emerging-threats ./rules-placeholder ./rules-threat-hunting -type f -name "*.yml")
