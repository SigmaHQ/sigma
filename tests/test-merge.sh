#!/bin/bash

COVERAGE=${COVERAGE:-coverage}

for f in $(find rules/ -type f -name '*.yml')
do
    echo -n .
    if ! $COVERAGE run -a --include=tools/* tools/merge_sigma $f > /dev/null
    then
        echo "[ERROR] Error in file " $f
        exit 1
    fi
done
