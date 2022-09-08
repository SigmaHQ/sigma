# Release Notes

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from version 0.14.0.

## 0.22 - 2022-09-08

### Added

* 'windash' modifier
* DNIF backend
* Hedera backend
* StreamAlert backend
* SQLite backend can handle null values.
* Support for different Windows log sources.

### Changed

* Various config improvements.

### Fixed

* Wrapping expressions from expanding modifiers into ORed subexpressions.
* Various mapping fixes.

## 0.21 - 2022-04-08

### Added

* Azure Sentinel backend
* OpenSearch Monitor backend
* Hawk backend
* Datadog backend
* FortiSIEM backend
* Lacework agent data support
* Athena SQL backend
* Regex support in SQLite backend
* Additional field mappings

### Changed

* Log source refactoring

### Fixed

* Mapping fixes
* Various bugfixes
* Disabled problematic optimization

## 0.20 - 2021-08-14

### Added

* Devo backend
* Fields selection added to SQL backend
* Linux/MacOS support for MDATP backend
* Output results as generic YAML/JSON
* Hash normalization option (hash_normalize) for Elasticsearch wildcard handling
* ALA AWS Cloudtrail and Azure mappings
* Logrhytm backend
* Splunk Data Models backend
* Further log sources used in open source Sigma ruleset
* CarbonBlack EDR backend
* Elastic EQL backend
* Additional conversion selection filters
* Filter negation
* Specify table in SQL backend
* Generic registry event log source
* Chronicle backend

### Changed

* Elastic Watcher backend populates name attribute instead of title.
* One item list optimization.
* Updated Winlogbeat mapping
* Generic mapping for Powershell backend

### Fixed

* Elastalert multi output file
* Fixed duplicate output in ElastAlert backend
* Escaping in Graylog backend
* es-rule ndjson output
* Various fixes of known bugs

## 0.19.1 - 2021-02-28

### Changed

* Added LGPL license to distribution

## 0.19 - 2021-02-23

### Added

* New parameters for Elastic backends
* Various field mappings
* FireEye Helix backend
* Generic log source image_load
* Kibana NDJSON backend
* uberAgent ESA backend
* SumoLogic CSE backend

### Changed

* Updated mdatp backend fields
* QRadar query generation optimized
* MDATP: case insensitive search

### Fixed

* Fixing Qradar implementation for create valid AQL queries
* Nested conditions
* Various minor bug fixes

## 0.18.1 - 2020-08-25

Release created for technical reasons (issues with extended README and PyPI), no real changes done.

## 0.18.0 - 2020-08-25

### Added

* C# backend
* STIX backend
* Options to xpack-watcher backend (action_throttle_period, mail_from acaw, mail_profile and other)
* More generic log sources
* Windows Defender log sources
* Generic DNS query log source
* AppLocker log source

### Changed

* Improved backend and configuration descriptions
* Microsoft Defender ATP mapping updated
* Improved handling of wildcards in Elastic backends

### Fixed

* Powershell backend: key name was incorrectly added into regular expression
* Grouping issue in Carbon Black backend
* Handling of default field mapping in case field is referenced multiple from a rule
* Code cleanup and various fixes
* Log source mappings in configurations
* Handling of conditional field mappings by Elastic backends

## 0.17.0 - 2020-06-12

### Added

* LOGIQ Backend (logiq)
* CarbonBlack backend (carbonblack) and field mappings
* Elasticsearch detection rule backend (es-rule)
* ee-outliers backend
* CrowdStrike backend (crowdstrike)
* Humio backend (humio)
* Aggregations in SQL backend
* SQLite backend (sqlite)
* AWS Cloudtrail ECS mappings
* Overrides
* Zeek configurations for various backends
* Case-insensitive matching for Elasticsearch
* ECS proxy mappings
* RuleName field mapping for Winlogbeat
* sigma2attack tool

### Changed

* Improved usage of keyword fields for Elasticsearch-based backends
* Splunk XML backend rule titles from sigma rule instead of file name
* Moved backend option list to --help-backend
* Microsoft Defender ATP schema improvements

### Fixed

* Splunx XML rule name is now set to rule title
* Backend list deduplicated
* Wrong escaping of wildcard at end of value when startswith modifier is used.
* Direct execution of tools on Windows systems by addition of script entry points

## 0.16.0 - 2020-02-25

### Added

* Proxy field names to ECS mapping (ecs-proxy) configuration
* False positives metadata to LimaCharlie backend
* Additional aggregation capabilitied for es-dsl backend.
* Azure log analytics rule backend (ala-rule)
* SQL backend
* Splunk Zeek sourcetype mapping config
* sigma2attack script
* Carbon Black backend and configuration
* ArcSight ESM backend
* Elasticsearch detection rule backend

### Changed

* Kibana object id is now Sigma rule id if available. Else
  the old naming scheme is used.
* sigma2misp: replacement of deprecated method usage.
* Various configuration updates
* Extended ArcSight mapping

### Fixed

* Fixed aggregation queries for Elastalert backend
* Fixed aggregation queries for es-dsl backend
* Backend and configuration lists are sorted.
* Escaping in ala backend

## 0.15.0 - 2019-12-06

### Added

* sigma-uuid tool for addition and check of Sigma rule identifiers
* Default configurations
* Restriction of compared rules in sigma-similarity
* Regular expression support in es-dsl backend
* LimaCharlie support for proxy rule category
* Source distribution for PyPI

### Changed

* Type errors are now ignored with -I

### Fixed

* Removed wrong mapping of CommandLine field mapping in THOR config

## 0.14 - 2019-11-10

### Added

* sigma-similarity tool
* LimaCharlie backend
* Default configurations for some backends that are used if no configuration is passed.
* Regular expression support for es-dsl backend (propagates to backends derived from this like elastalert-dsl)
* Value modifiers:
    * startswith
    * endswith

### Changed

* Removal of line breaks in elastalert output
* Searches not bound to fields are restricted to keyword fields in es-qs backend
* Graylog backend now based on es-qs backend

### Fixed

* Removed ProcessCommandLine mapping for Windows Security EventID 4688 in generic
  process creation log source configuration.

## 0.13 - 2019-10-21

### Added

* Index mappings for Sumologic
* Malicious cmdlets in mdatp
* QRadar support for keyword searches
* QRadar mapping improvements
* QRadar field selection
* QRadar type regex modifier support
* Elasticsearch keyword field blacklisting with wildcards
* Added dateField configuration parameter in xpack-watcher backend
* Field mappings in configurations
* Field name mapping for conditional fields
* Value modifiers:
    * utf16
    * utf16le
    * wide
    * utf16be

### Changed

* Improved --backend-config help text

### Fixed

* Backend errors in ala
* Slash escaping within es-dsl wildcard queries
* QRadar backend config
* QRadar field name and value escaping and handling
* Elasticsearch wildcard detection pattern
* Aggregation on keyword field in es-dsl backend

## 0.12.1 - 2019-08-05

### Fixed

* Missing build dependency

## 0.12 - 2019-08-01

### Added

* Usage of "Channel" field in ELK Windows configuration
* Fields to mappings
* xpack-watcher actions index and webhook
* Config for Winlogbeat 7.x
* Value modifiers
* Regular expression support

### Changed

* Warning/error messages
* Sumologic value cleaning
* Explicit OR for Elasticsearch query strings
* Listing of available configurations on missing configuration error

### Fixed

* Conditions in es-dsl backend
* Sumologic handling of null values
* Ignore timeframe detection keyword in all/any of conditions
