#!/bin/bash


curl -XPUT 'localhost:9200/test?pretty' -H 'Content-Type: application/json' -d'
{
    "settings" : {
        "index" : {
            "number_of_shards" : 1, 
            "number_of_replicas" : 0 
        }
    }
}
'
tools/sigmac -t es-qs -Orulecomment -I -r rules/ > es-queries.txt
while read line
do
    if [[ $line == \#* ]]
    then
        rule=${line##\# }
    elif [[ ! -z "$line" ]]
    then
        echo "Rule: $rule"
        echo "Query: $line"
        curl -s -H 'Content-Type: application/json' -d "$(jq -n --arg query "$line" -f tests/es-query-template.jq)" localhost:9200/test/_doc/_validate/query?pretty | jq -e '.valid' > /dev/null
        if [[ $? != 0 ]]
        then
            echo "Error!" >&2
            exit 1
        else
            echo "Ok"
            echo
        fi
    fi
done < es-queries.txt
