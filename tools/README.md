# Sigma Tools

This folder contains libraries and the following command line tools:

* *sigmac*: converter between Sigma rules and SIEM queries
* *merge_sigma*: Merge Sigma collections into simple Sigma rules.
* *sigma2misp*: Import Sigma rules to MISP events.

# Sigmac

The Sigmac is one of the most important files, as this is what sets the correct fields that your backend/database will use after being translated from the (original) log source's field names.
Please read below to understand how a SIGMAC is constructed. Additionally, see [Choosing the Right Sigmac](#choosing-the-right-sigmac) for an idea of which file and command line options (if applicable) that will best suite your environment.

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

* Simple: the source field name corresponds to exactly one target field name given as string. Example: `EventID: EventCode` for translation of Windows event identifiers between Sigma and Splunk.
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

## Choosing the right SIGMAC

The section will show you which `-c` option (the Sigmac) and which `--backend-option`(s) to use. The rest of SIGMA should be run as normal.
For example, run the rest of the command as you normally would, regarding the `-t` (target backend) and which rule(s) you are performing SIGMA on.

If the target backend/database does not do a lot of field renaming/normalization than the selection of which Sigmac to use is easier to determine. However, this section will help guide you in this decision.

### Elasticsearch or ELK

For this backend, there are two very important components. One is the field name and the other is the the way the value for the field name are analyzed AKA searchable in the Elasticsearch database. If you are interested in understand how this is important, you can read more [here](https://socprime.com/blog/elastic-for-security-analysts-part-1-searching-strings/) to understand the impact between `keyword` types and `text` types.
You have a few different variations of what could be the correct Sigmac to use. Based on the version of Elasticsearch, using ECS or not, using certain Beat's settings enabled or not, and so on.

In order to aide in the decision of the correct Sigmac there are a few quick questions to ask yourself and based on those answers will be which one to use.
Please note the answer to each question. It is OK to not know the answer to each question and in fact is very common (that's OK).

1. What version of [Filebeat](https://www.elastic.co/beats/filebeat) are you using (you may not be using this at all).
2. Are you using [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)?
3. What index do your store the log source's data in? Some examples:
   * Window's logs are most likely in `winlogbeat-*`
   * Linux logs are most likely in `filebeat-*`
   * Zeek/Bro data is most likely in `filebeat-*`
   * If you are using logstash, data is most likely in `logstash-*`
4. If you are using Filebeat, are you using the module enabled? Here is link showing the description for Windows log [Security Channel](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-module-security.html)

Now choose your data source:
* [Windows Event Logs](#elastic-windows-event-log--sysmon-data-configurations)
* [Zeek](#elastic---zeek-fka-bro--corelight-data)

### Elastic - Zeek (FKA Bro) / Corelight Data

* Corelight's implementation of ECS:
`-c tools/config/ecs-zeek-corelight.yml  --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option keyword_whitelist="event.dataset,source.ip,destination.ip,source.port,destination.port,*bytes*"`
example of the full command running on all the proxy rules converting to a Kibana (lucene) query:
`tools/sigmac -t es-qs -c tools/config/ecs-zeek-corelight.yml  --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option keyword_whitelist="event.dataset,source.ip,destination.ip,source.port,destination.port,*bytes*" rules/proxy/*`
* Filebeat version 7 or higher and or Elastic's implementation:
`-c tools/config/ecs-zeek-elastic-beats-implementation.yml  --backend-option keyword_base_fields="*"`
* Using logstash and NOT using ECS:
`-c tools/config/logstash-zeek-default-json.yml`

### Elastic Windows Event Log / Sysmon Data Configurations

**index templates**

If you are able, because this will be one of the best ways to determine which options to use - run the following command. Take the output from question 3 and replace in the example command `winlogbeat` with index. You can run this from the CLI against your Elasticsearch instance or from Kibana Dev Tools.
You will only need to use the first index template pattern. Look under the section `dynamic_templates` and then look for `strings_as_keyword`. Under that section, is there a `strings_as_keyword` ? If so take note.

`curl -XGET "http://127.0.0.1:9200/winlogbeat-*/_mapping/?filter_path=*.mappings.dynamic_templates*,*.index_patterns"`

The next question to ask yourself, is do you want easily bypassable queries due to case sensitive searches? Take note of yes/no.

Now lets determine which options and Sigmac to use.

**Sigmac's `-c` option**

1. Using winlogbeat version 6 or less `-c tools/config/winlogbeat-old.yml`
2. Using winlogbeat version 7 or higher without modules enabled (answer from **question 4**) and `strings_as_keyword` does not contain `text` `-c tools/config/winlogbeat-old.yml`
3. Using winlogbeat version 7 or higher with modules enabled (answer from **question 4**) `-c tools/config/winlogbeat-modules-enabled.yml`

**Backend options `--backend-option`**
You can add the following depending on additional information from your answers/input above.

1. If you are using ECS, your data is going to `winlogbeat-*` index, or your default field is a keyword type then add the following to your SIGMA command: `--backend-option keyword_field="" `
    * If you want to prevent case sensitive bypasses you can add the following to your command: `--backend-option case_insensitive_whitelist="*"`
    * If you want to prevent case sensitive bypasses but only for certain fields, you can use an option like this: `-backend-option keyword_field="" --backend-option case_insensitive_whitelist="*CommandLine*, *ProcessName*, *Image*, process.*, *FileName*, *Path*, *ServiceName*, *ShareName*, file.*, *Directory*, *directory*, *hash*, *Hash*, *Object*, ComputerName, *Subject*, *Target*, *Service*"`

1. If you are using analyzed (text) fields or your index template portion of `strings_as_keyword` contains `text` then you can add the following:

    ```bash
    --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text"
    ```

1. If you only have some analyzed fields then you would use an example like this:

    ```bash
    --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image"
    ```

1. If you only have some analyzed fields then you would use an example like this:

    ```bash
    --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image"
    ```
1. Use an analyzed field or different field for queries that contain wildcard(s)

    ```bash
    --backend-option wildcard_use_keyword="false"
    ```

### Elastic - Some Final Examples

So putting it all together to help show everything from above, here are some "full" examples:

* base field keyword & no analyzed field w/ case insensitivity (covers elastic 7 with beats/ecs (default)mappings) and using winlogbeat with modules enabled. Also, keeps `winlog.channel` from making case insensitive as is not necessary (ie: the `keyword_whitelist` option)

```bash
tools/sigmac -t es-qs -c tools/config/winlogbeat-modules-enabled.yml --backend-option keyword_field="" --backend-option case_insensitive_whitelist="*" --backend-option keyword_whitelist="winlog.channel" rules/windows/process_creation/win_office_shell.yml
```

* base field keyword & subfield is analyzed(.text) and winlogbeat with modules enabled

```bash
tools/sigmac -t es-qs -c tools/config/winlogbeat-modules-enabled.yml --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" rules/windows/process_creation/win_office_shell.yml
```

* base field keyword & only some analyzed fields and winlogbeat without modules enabled

```bash
tools/sigmac -t es-qs -c tools/config/winlogbeat.yml  --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image" rules/windows/process_creation/win_office_shell.yml
```

* using beats/ecs Elastic 7 with case insensitive and some .text fields and winlogbeat without modules enabled

```bash
tools/sigmac -t es-qs -c tools/config/winlogbeat.yml --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option keyword_whitelist="winlog.channel,winlog.event_id" --backend-option case_insensitive_whitelist="*" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image" rules/windows/process_creation/win_office_shell.yml
```

* using keyword as a subfield and custom analyzed field as a subfield with winlogbeat mappings

```bash
tools/sigmac -t es-qs -c tools/config/winlogbeat.yml --backend-option keyword_field=".keyword" --backend-option analyzed_sub_field_name=".security" rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

### Devo
Devo backend admits several configurations that, based on the data source type, will apply a specific mapping and
will point to the proper Devo table. The current available configurations are:
* `devo-windows`, for windows sources
* `devo-web`, for generic web sources (webserver, apache, proxy...)
* `devo-network`, for generic network sources (firewall, dns...)

These backend configurations will specify the Devo table to build the query upon, and the output query will reference such
table if the rule sources matches the configuration sources.

For example, in order to translate a windows-related Sigma rule, one would use:

```bash
tools/sigmac -t devo -c tools/config/devo-windows.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```