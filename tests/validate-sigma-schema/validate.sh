#!/bin/bash

echo "Validating Sigma rules against sigma-schema.json"
check-jsonschema --schemafile $(python tests/validate-sigma-schema/validate.py schema) $(python tests/validate-sigma-schema/validate.py rules)
