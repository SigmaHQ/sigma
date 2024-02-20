#!/bin/bash

echo "Validating Sigma rules against sigma-schema.json"
# SIGMA_REPO_PATH is a variable that contains the path to the Sigma repository,
# DO NOT USE THIS VARIABLE IN YOUR CODE, IT IS FOR TESTING PURPOSES ONLY IN SIGMA REPOSITORY.
check-jsonschema --schemafile $(python ./${SIGMA_REPO_PATH}validate.py schema) $(python ./${SIGMA_REPO_PATH}validate.py rules)
