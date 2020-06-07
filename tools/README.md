# Sigma Tools

This folder contains libraries and the following command line tools:

* *sigmac*: converter between Sigma rules and SIEM queries
* *merge_sigma*: Merge Sigma collections into simple Sigma rules.
* *sigma2misp*: Import Sigma rules to MISP events.

# Sigmac

## Configuration File

The configuration file contains mappings for the target environments:

* between generic Sigma field names and those used in the target environment
* between log source identifiers from Sigma and...
  * ...index names from target
  * ...conditions that should be added to generated expression (e.g. EventLog: Microsoft-Windows-Sysmon) with AND.
* between placeholders in sigma rules and lists that describe their values in the target environment

The mappings are configured in a YAML file with the following format:

```yaml
title: short description of configuration
order: numeric value
backends:
  - backend_1
  - backend_2
  - ...
fieldmappings:
  sigma_fieldname_1: target_fieldname   # Simple mapping
  sigma_fieldname_2:                    # Multiple mappings
    - target_fieldname_1
    - target_fieldname_2
  sigma_fieldname_3:                    # Conditional mapping
    field1=value1:
    field2=value2:
      - target_fieldname_1
      - target_fieldname_2
logsources:
  sigma_logsource:
    category: ...
    product: ...
    service: ...
    index:
      - target_indexname1
      - target_indexname2
    conditions:
      field1: value1
      field2: value2
logsourcemerging: and/or
defaultindex: indexname
placeholders:
  name1:
    - value1
    - value2
  name2: value
```

## Metadata

A configuration should contain the following attributes:

* **title**: Short description of configuration shown in list printed by converter on request.
* **order**: Numeric value that determines allowed order of usage. A configuration *B* can only be applied after another configuration *A* if order of B is higher or equal to order of A. The Sigma converter enforces this. Convention:
  * 10: Configurations for generic log sources
  * 20: Backend-specific configuration
* **backends**: List of backend names. The configuration can't be used with backends not listed here. Don't define for generic configurations.

## Field Mappings

Field mappings in the *fieldmappings* section map between Sigma field names and field names used in target SIEM systems. There are three types of field mappings:

* Simple: the source field name corresponds to exactly one target field name given as string. Exmaple: `EventID: EventCode` for translation of Windows event identifiers between Sigma and Splunk.
* Multiple: a source field corresponds to a list of target fields. Sigmac generates an OR condition that covers all field names. This can be useful in configuration change and migration scenarios, when field names change. A further use case is when the SIEM normalizes one source field name into different target field names and the exact rules are unknown.
* Conditional: a source field is translated to one or multiple target field names depending on values from other fields in specific rules. This is useful in scenarios where the SIEM maps the same Sigma field to different target field names depending on the event or log type, like Logpoint.

While simple and multiple mapping type are quite straightforward, conditional mappings require further explanation. The mapping is provided as map where the keys have the following format:

* field=value: condition that must be fulfilled for execution of the given translation
* default: mapping that is used if no condition matches.

Sigmac applies conditional mappings as follows:

1. All conditions are mapped against all field:value pairs of the rule. It merges all pairs into one table and is therefore not able to distinguish between different definitions. Matching mappings are collected in a list.
2. If the list is empty, the default mapping is used.
3. The result set of target field name mappings is translated into an OR condition, similar to multiple field mappings. If no mapping could be determined, the Sigma field name is used.

Use the *fieldlist* backend to determine all field names used by rules. Example:

```bash
$ tools/sigmac.py -r -t fieldlist rules/windows/ 2>/dev/null | sort -u
AccessMask
CallTrace
CommandLine
[...]
TicketOptions
Type
```

## Log Source Mappings

Each log source definition must contain at least one category, product or service element that corresponds to the same fields in the logsources part of sigma rules. If more than one field is given, all must match (AND).

The *index* field can contain a string or a list of strings. They a converted to the target expression language in a way that the rule is searched in all given index patterns.

The conditions part can be used to define *field: value* conditions if only a subset of the given indices is relevant. All fields are linked with logical AND and the resulting expression is also lined with AND against the expression generated from the sigma rule.

Example: a logstash configuration passes all Windows logs in one index. For Sysmon only events that match *EventLog:"Microsoft-Windows-Sysmon" are relevant. The config looks as follows:

```yaml
...
logsources:
  sysmon:
    product: sysmon
    index: logstash-windows-*
    conditions:
      EventLog: Microsoft-Windows-Sysmon
...
```

If multiple log source definitions match, the result is merged from all matching rules. The parameter *logsourcemerging* determines how conditions are merged. The following methods are supported:

* and (default): merge all conditions with logical AND.
* or: merge all conditions with logical OR.

This enables to define logsources hierarchically, e.g.:

```yaml
logsources:
  windows:
    product: windows
    index: logstash-windows-*
  windows-application:
    product: windows
    service: application
    conditions:
      EventLog: Application
  windows-security:
    product: windows
    service: security
    conditions:
      EventLog: Security
```

Log source windows configures an index name. Log sources windows-application and windows-security define additional conditions for matching events in the windows indices.

The keyword defaultindex defines one or multiple index patterns that are used if the above calculation doesn't results in at least one index name.

## Addition of Target Formats

Addition of a target format is done by development of a backend class. A backend class gets a parse tree as input and must translate parse tree nodes into the target format.

## Translation Process

1. Parsing YAML
2. Parsing of Condition
3. Internal representation of condition as parse tree
4. Attachment of definitions into corresponding parse tree nodes
5. Translation of field and log source identifiers into target names
6. Translation of parse tree into target format (backend classes)

## Backend Configuration Files

You can also pass backend options from a configuration file, which simplifies the CLI usage.

One can specify both individual backend options (--backend-option) and specify a configuration file as well - in this case, options are merged, and priority is given to the options passed via the CLI.

Sample usages:

```yaml
# Backend configuration file (here for Elastalert)
$ cat backend_config.yml 
alert_methods: email
emails: alerts@mydomain.tld
smtp_host: smtp.google.com
from_addr: noreply@mydomain.tld
expo_realert_time: 10m

# Rule to compile
$ RULE=rules/windows/builtin/win_susp_sam_dump.yml

# Generate an elastalert rule and take options from the configuration file
$ python3 tools/sigmac $RULE -t elastalert --backend-config backend_config.yml
alert:
- email
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other
  password dumpers
email:
- alerts@mydomain.tld
filter:
- query:
    query_string:
      query: (EventID:"16" AND "*\\AppData\\Local\\Temp\\SAM\-*.dmp\ *")
from_addr: noreply@mydomain.tld
index: logstash-*
name: SAM-Dump-to-AppData_0
priority: 2
realert:
  minutes: 0
smtp_host: smtp.google.com
type: any

# Override an option from the configuration file via the CLI
$ python3 tools/sigmac $RULE -t elastalert --backend-config backend_config.yml --backend-option smtp_host=smtp.mailgun.com
alert:
- email
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other
  password dumpers
email:
- alerts@mydomain.tld
filter:
- query:
    query_string:
      query: (EventID:"16" AND "*\\AppData\\Local\\Temp\\SAM\-*.dmp\ *")
from_addr: noreply@mydomain.tld
index: logstash-*
name: SAM-Dump-to-AppData_0
priority: 2
realert:
  minutes: 0
smtp_host: smtp.mailgun.com
type: any
```
