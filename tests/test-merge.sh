#!/bin/bash

for f in $(find rules/ -type f -name '*.yml')
do
    echo -n .
    if ! coverage run -a --include=tools/* tools/merge_sigma $f > /dev/null
    then
        exit 1
    fi
done
