# Security Policy

## Supported versions

Security fixes are made on the `master` branch and ship in the next rule release. Older rule release packages are not updated.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/sigma/security/advisories/new>).
If you cannot use GitHub, open a public issue that says only that you have a security report and asks for a private contact. Do not include any details in that issue.

Please include:

- the affected rule, workflow or script, and the steps or input that reproduce the problem;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

This repository holds the SigmaHQ rule set together with the tests, scripts and GitHub Actions workflows that validate and release it. The following are in scope:

- **CI/CD and release integrity:** weaknesses in workflows or scripts (for example untrusted pull-request content reaching a privileged workflow, script injection, or exposed tokens) that could let an outsider change `master`, a release package or published artefacts.
- **Malicious rule content:** a rule, pipeline or test file that is crafted to exploit tools that process this repository (converters, validators, SIEM importers), for example to inject into generated queries or to trigger code execution. If the root cause is in a tool, report it to that tool's repository as well.
- **Sensitive data:** credentials, personal data or other secrets committed in rules, test data or regression logs.

**Out of scope (report publicly as bugs or rule issues):**

- False positives, false negatives, wrong log sources or outdated detections. Please open an issue or a pull request; these are handled publicly so fixes reach users quickly.
- Detection gaps for a new technique. Please contribute a rule.

## Our process

| Step                                                                          | Target                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------- |
| Acknowledge the report                                                        | within 5 working days                         |
| Initial assessment and severity (CVSS 3.1)                                    | within 14 days                                |
| Fix developed in the advisory's temporary private fork                        | as soon as practical, normally within 90 days |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                            |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix affects other SigmaHQ projects, we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
