# Repository Improvements Log

This document records maintenance changes made to the **tooling and CI** of this
repository (not to the detection rules themselves). Each entry states *what*
changed, *why*, and *how to operate it going forward*.

---

## 2026-06-23 — Reproducible & cached CI dependencies

### Summary

CI previously installed its Python dependencies unpinned (`pip install pysigma`,
`pip install sigma-cli`, `pip install PyYAML colorama`). This made the build
**non-reproducible**: any upstream release of pySigma, sigma-cli, or the SigmaHQ
validators could turn a contributor's PR red without a single change on our side,
and every job re-downloaded every package from scratch on every run.

Dependencies are now **pinned in requirements files** and CI **caches the pip
download directory**, keyed on those files. This is the highest-leverage change
available because `sigma-test.yml` runs on **every push, pull request, and merge
group** — it is the gate every contribution passes through.

### What changed

| File | Change | Why |
|------|--------|-----|
| `tests/requirements.txt` *(new)* | Pins `PyYAML==6.0.3`, `colorama==0.4.6` | Deps for the legacy Python harness (`test_rules.py`, `test_logsource.py`, `regression_tests_runner.py`). Exact pins = reproducible runs. |
| `tests/requirements-validation.txt` *(new)* | Pins `pysigma==1.3.3`, `sigma-cli==3.0.2`, `pySigma-validators-sigmahq==0.20.2` | Deps for `sigma check`. The validators encode the SigmaHQ conventions, so a floating patch could silently change the rule pass/fail bar for all open PRs. |
| `.github/workflows/sigma-test.yml` | 3 jobs now `pip install -r ...` instead of inline package lists; all 3 `setup-python` steps gained `cache: pip` + `cache-dependency-path: tests/requirements*.txt` | Single source of truth for versions; cached installs cut per-job setup time. |
| `.github/workflows/regression-tests.yml` | `pip install pyyaml` → `pip install -r tests/requirements.txt`; added the same pip cache | Consistency + caching for the regression job too. |

### Notable decision: validators pin tightened

The validators were previously `pySigma-validators-sigmahq==0.20.*` (floating
patch). They are now `==0.20.2` (exact). Trade-off: we lose automatic patch
pickup, but we gain that **convention changes become an explicit, reviewable
commit** instead of a surprise CI failure landing on unrelated PRs. For a shared
CI gate, reproducibility outweighs auto-bumping.

### How to bump dependencies

1. Edit the version in `tests/requirements.txt` and/or
   `tests/requirements-validation.txt`.
2. Validate locally before committing:
   ```bash
   sigma check --fail-on-error --fail-on-issues \
     --validation-config tests/sigma_cli_conf.yml rules*
   python tests/test_rules.py
   python tests/test_logsource.py
   ```
3. Fix any rule issues newly surfaced by the bump, then commit the requirements
   change together with those fixes. CI re-caches automatically (the cache key is
   the hash of `tests/requirements*.txt`).

### Verification done

- Both edited workflow files parse as valid YAML.
- `.yamllint` ignores `.github/` and `tests/`, so the new files and workflow
  edits cannot break the `yamllint` job.
- Pinned versions were confirmed against PyPI as the current latest and are
  mutually compatible.

---

## 2026-06-23 — README rule-type count drift

### Summary

`README.md` stated "Currently the repository offers **three** types of rules:"
immediately above a list of **five** types (Generic, Threat Hunting, Emerging
Threat, Compliance, Placeholder). Changed "three" → "the following" so the count
cannot drift again as rule categories are added or removed.

| File | Change |
|------|--------|
| `README.md` | "offers three types of rules" → "offers the following types of rules" |

---

## Recommended follow-ups (not yet done)

These were identified but intentionally left out to keep the change set small,
low-risk, and easy to review:

1. **Retire the legacy `tests/test_rules.py` (2,022 lines).** Its own header notes
   most checks are now covered by pySigma / sigma-cli validators, and large blocks
   are already commented out. Migrate any still-unique checks into
   `pySigma-validators-sigmahq` and delete the rest to cut maintenance.
2. **Pin the remaining scheduled workflows** the same way:
   `ref-archiver.yml` (`requests`), `sigma-rule-deprecated.yml` (`pySigma`). Lower
   priority — they are scheduled, not per-PR gates.
3. **Add a `.pre-commit-config.yaml`** (yamllint + `sigma check`) so contributors
   catch issues before opening a PR.
4. **Empty `rules-dfir/` directory** — contains 0 rules and is not referenced in
   the README. Either populate it or remove it. Left untouched here in case it is
   an intentional placeholder for an upcoming category.
5. **Add a Python linter** (e.g. ruff) for `tests/*.py` — the only executable code
   in the repo is currently unlinted.
