# Sigma Regression Testing

Regression tests verify that Sigma rules actually match the events they are
supposed to detect. Each rule (rules with status `test` or `stable` must) points to an
`info.yml` describing one or more test cases, each backed by a real event
sample (EVTX or JSON). CI runs every sample against its rule and fails if the
expected number of matches is not produced.

The runner lives at [`tests/regression_tests_runner.py`](../tests/regression_tests_runner.py)
and runs on every push/PR via [`.github/workflows/regression-tests.yml`](../.github/workflows/regression-tests.yml).

## Layout

```
regression_data/
├── pipelines/                 # Sigma conversion pipelines used by JSON tests
└── rules/<product>/<category>/<rule_name>/
    ├── info.yml               # test definitions for the rule
    ├── <rule_id>.evtx         # EVTX sample (name must equal rule id)
    └── <rule_id>.json         # optional JSON/NDJSON sample (name must equal rule id)
```

The rule file references its tests with:

```yaml
regression_tests_path: ../../regression_data/rules/windows/process_creation/<rule_name>/info.yml
```

## Supported Types

### EVTX

Runs [`evtx-sigma-checker`](https://github.com/NextronSystems/evtx-baseline)
against the `.evtx` sample using the THOR log-source config and the rule
directory.

```yaml
- name: Positive Detection Test
  type: evtx
  provider: Microsoft-Windows-Sysmon # Not used atm
  match_count: 1
  path: regression_data/rules/windows/process_creation/<rule_name>/<rule_id>.evtx
```

The `.evtx` file name must equal the rule `id`.

### Json / NDJson / JsonL

`json` means a single JSON object, while `ndjson`/`jsonl` mean newline-delimited
JSON objects (one object per line).

The rule is compiled to a `golang_expr` query with `sigma convert` (applying any
listed `pipelines` and `filters`), then run against the event sample by
`json_checker`.

```yaml
- name: Positive Detection Test
  type: json          # or: ndjson, jsonl
  match_count: 1
  pipelines:
      - regression_data/pipelines/process_creation_fieldmapping.yml
  path: regression_data/rules/windows/process_creation/<rule_name>/<rule_id>.json
```

`pipelines` and `filters` are optional and with no pipeline, the rule is converted with `--without-pipeline`.

## info.yml Format

```yaml
id: 242d26e0-1ce5-4a34-960d-144f34f60e37   # id of this test-info file
description: N/A
date: 2025-12-25
author: Author Name
rule_metadata:
    - id: 7dbbcac2-57a0-45ac-b306-ff30a8bd2981   # must match the rule file id
      title: Windows AMSI Related Registry Tampering Via CommandLine
regression_tests_info:
    - name: Positive Detection Test
      type: evtx
      provider: Microsoft-Windows-Sysmon # Not used atm
      match_count: 1
      path: regression_data/rules/.../<rule_id>.evtx
    - name: Positive Detection Test
      type: json
      match_count: 1
      pipelines:
          - regression_data/pipelines/process_creation_fieldmapping.yml
      path: regression_data/rules/.../<rule_id>.json
```

Fields per entry in `regression_tests_info`:

| Field         | Required | Description                                                        |
|---------------|----------|--------------------------------------------------------------------|
| `name`        | no       | Human-readable test name.                                          |
| `type`        | yes      | `evtx`, `json`, `ndjson`, or `jsonl`.                              |
| `path`        | yes      | Path to the event sample.                                          |
| `match_count` | no       | Expected number of matches. Fails if fewer; warns if more.        |
| `provider`    | no       | Event provider (informational, used by EVTX tests).               |
| `pipelines`   | no       | Sigma pipelines applied before conversion (JSON types).           |
| `filters`     | no       | Sigma filters applied during conversion (JSON types).             |

If `match_count` is omitted, the test passes when there is at least one match.

## Validation rules

- Rules with status `test` or `stable` must define `regression_tests_path`
  (enforced unless `--ignore-validation`).
- Referenced `info.yml` and sample files must exist.
- Rule `id` == `info.yml`, `rule_metadata[0].id` == EVTX/JSON sample file name.

The runner exits non-zero on any failed test, missing file, or inconsistency.
