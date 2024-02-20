#!/bin/bash

echo "Validating Sigma rules against sigma-schema.json"
# SIGMA_REPO_PATH is a variable that contains the path to the Sigma repository,
# DO NOT USE THIS VARIABLE IN YOUR CODE, IT IS FOR TESTING PURPOSES ONLY IN SIGMA REPOSITORY.
check-jsonschema --schemafile $(python tests/validate-sigma-schema/validate.py schema) $(python tests/validate-sigma-schema/validate.py rules)
