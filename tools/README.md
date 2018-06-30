This package contains libraries for processing of [Sigma rules](https://github.com/Neo23x0/sigma) and the following
command line tools:

* *sigmac*: converter between Sigma rules and SIEM queries:
    * Elasticsearch query strings
    * Kibana JSON with searches
    * Splunk SPL queries
    * Elasticsearch X-Pack Watcher
    * Logpoint queries
* *merge_sigma*: Merge Sigma collections into simple Sigma rules.

## Sigmac

### Usage

      usage: sigmac [-h] [--recurse] [--filter FILTER]
                    [--target {es-dsl,es-qs,graylog,kibana,xpack-watcher,logpoint,splunk,grep,fieldlist}]
                    [--target-list] [--config CONFIG] [--output OUTPUT]
                    [--backend-option BACKEND_OPTION] [--defer-abort]
                    [--ignore-not-implemented] [--verbose] [--debug]
                    [inputs [inputs ...]]

      Convert Sigma rules into SIEM signatures.

      positional arguments:
        inputs                Sigma input files

      optional arguments:
        -h, --help            show this help message and exit
        --recurse, -r         Recurse into subdirectories (not yet implemented)
        --filter FILTER, -f FILTER
                              Define comma-separated filters that must match (AND-
                              linked) to rule to be processed. Valid filters:
                              level<=x, level>=x, level=x, status=y, logsource=z. x
                              is one of: low, medium, high, critical. y is one of:
                              experimental, testing, stable. z is a word appearing
                              in an arbitrary log source attribute. Multiple log
                              source specifications are AND linked.
        --target {es-dsl,es-qs,graylog,kibana,xpack-watcher,logpoint,splunk,grep,fieldlist}, -t {es-dsl,es-qs,graylog,kibana,xpack-watcher,logpoint,splunk,grep,fieldlist}
                              Output target format
        --target-list, -l     List available output target formats
        --config CONFIG, -c CONFIG
                              Configuration with field name and index mapping for
                              target environment (not yet implemented)
        --output OUTPUT, -o OUTPUT
                              Output file or filename prefix if multiple files are
                              generated (not yet implemented)
        --backend-option BACKEND_OPTION, -O BACKEND_OPTION
                              Options and switches that are passed to the backend
        --defer-abort, -d     Don't abort on parse or conversion errors, proceed
                              with next rule. The exit code from the last error is
                              returned
        --ignore-not-implemented, -I
                              Only return error codes for parse errors and ignore
                              errors for rules with not implemented features
        --verbose, -v         Be verbose
        --debug, -D           Debugging output

      Backend options:
        es-dsl
          es        : Host and port of Elasticsearch instance (default: http://localhost:9200)
          output    : Output format: import = JSON search request, curl = Shell script that do the search queries via curl (default: import)
        es-qs
          rulecomment: Prefix generated query with comment containing title (default: False)
        graylog
          rulecomment: Prefix generated query with comment containing title (default: False)
        kibana
          output    : Output format: import = JSON file manually imported in Kibana, curl = Shell script that imports queries in Kibana via curl (jq is additionally required) (default: import)
          es        : Host and port of Elasticsearch instance (default: localhost:9200)
          index     : Kibana index (default: .kibana)
          prefix    : Title prefix of Sigma queries (default: Sigma: )
        xpack-watcher
          output    : Output format: curl = Shell script that imports queries in Watcher index with curl (default: curl)
          es        : Host and port of Elasticsearch instance (default: localhost:9200)
          mail      : Mail address for Watcher notification (only logging if not set) (default: None)
        logpoint
          rulecomment: Prefix generated query with comment containing title (default: False)
        splunk
          rulecomment: Prefix generated query with comment containing title (default: False)
