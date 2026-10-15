# Sigma Regression Testing

Regression tests verify that Sigma rules actually match the events they are
supposed to detect. Each `info.yml` under `regression_data/` describes one or
more test cases (each backed by a real EVTX or JSON event sample) and lists the
rule `id`s it applies to. The runner walks `regression_data/` for `info.yml`
files, looks up each rule by its `id`, and runs every sample against the rule,
failing if the expected number of matches is not produced. Rules with status
`test` or `stable` must have regression tests defined.

The runner lives at [`tests/regression_tests_runner.py`](../tests/regression_tests_runner.py)
and runs on every push/PR via [`.github/workflows/regression-tests.yml`](../.github/workflows/regression-tests.yml).

## Layout

```
regression_data/
├── pipelines/                 # Sigma conversion pipelines used by JSON tests
└── rules/<product>/<category>/<rule_name>/
    ├── info.yml               # test definitions, referencing rule(s) by id
    ├── <sample>.evtx          # EVTX sample
    └── <sample>.json          # optional JSON/NDJSON sample
```

Mirroring the rule tree as `rules/<product>/<category>/<rule_name>/` is best
practice for discoverability, but it is **not enforced**. The runner finds
tests by walking for `info.yml` files and resolving rules by `id`, so an
`info.yml` may live anywhere and a single test case can exercise multiple rules
(list several entries under `rules`).

Rules no longer declare a `regression_tests_path`. Instead each `info.yml`
references the rule(s) it tests by `id` (see below), and the runner resolves
them against the rule directories passed via `--rules-paths`.

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
  path: regression_data/rules/windows/process_creation/<rule_name>/<sample>.evtx
```

The sample is defined in the `path` field; the file name is arbitrary.

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
  path: regression_data/rules/windows/process_creation/<rule_name>/<sample>.json
```

`pipelines` and `filters` are optional and with no pipeline, the rule is converted with `--without-pipeline`.
A test case's `pipelines` take precedence over a root-level `pipelines` (see below).

## info.yml Format

```yaml
id: 242d26e0-1ce5-4a34-960d-144f34f60e37   # id of this test-info file
description: N/A
date: 2025-12-25
author: Author Name
pipelines:                                   # optional, fallback for test_cases
    - regression_data/pipelines/process_creation_fieldmapping.yml
rules:
    - id: 7dbbcac2-57a0-45ac-b306-ff30a8bd2981   # resolved against --rules-paths
test_cases:
    - name: Positive Detection Test
      type: evtx
      provider: Microsoft-Windows-Sysmon # Not used atm
      match_count: 1
      path: regression_data/rules/.../<sample>.evtx
    - name: Positive Detection Test
      type: json
      match_count: 1
      pipelines:                           # overrides the root-level pipelines
          - regression_data/pipelines/process_creation_fieldmapping.yml
      path: regression_data/rules/.../<sample>.json
```

A root-level `pipelines` applies to every test case that does not define its
own `pipelines`; a test case's `pipelines` always take precedence.

`pipelines` and `filters` are only used for JSON-based matching
(`json`/`ndjson`/`jsonl`), since they feed the `sigma convert` step. EVTX tests
run the rule directly via `evtx-sigma-checker` and ignore both fields.

Each entry in `rules` needs an `id` (looked up against `--rules-paths`).

Fields per entry in `test_cases`:

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

- Rules with status `test` or `stable` must have regression tests defined,
  i.e. be referenced by some `info.yml` (enforced unless `--ignore-validation`).
- Every `id` listed under `rules` in an `info.yml` must resolve to an existing
  rule file.
- Referenced sample files (the `path` of each test case) must exist.

The runner exits non-zero on any failed test, missing file, or missing rule.
