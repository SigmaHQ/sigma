# Contributing to Sigma 🧙‍♂️

First off, thank you for considering contributing to Sigma! Your help is invaluable in keeping this project up-to-date and useful for the community.

The following guidelines will help you understand how to contribute effectively.

## 📝 Reporting False Positives Or Proposing New Detection Rule Ideas 🔎

If you find a false positive or would like to propose a new detection rule idea but do not have the time to create one, please create a new issue on the [GitHub repository](https://github.com/SigmaHQ/sigma/issues/new/choose) by selecting one of the available templates.

## 🛠️ Submitting Pull Requests (PRs)

1. Fork the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) and clone your fork to your local machine.

2. Create a new branch for your changes:

```bash
git checkout -b your-feature-branch
```

3. Make your changes, and test them:

   3.1. **`test_logsource.py`** - validates that all rules reference valid log sources and field names:

   ```bash
   python tests/test_logsource.py
   ```

   3.2. **`test_rules.py`** - checks rules for structural issues, noncompliance, and common mistakes:

   ```bash
   python tests/test_rules.py
   ```

   3.3. **Sigma CLI validation** - runs schema and validation checks using Sigma CLI. Run this if you have the [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and [pySigma-validators-sigmahq](https://github.com/SigmaHQ/pySigma-validators) Python packages installed:

   ```bash
   sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml rules/ rules-emerging-threats/ rules-threat-hunting/ rules-compliance/
   ```

   3.4. **Baseline FP check** *(optional, Windows rules only)* - downloads clean Windows EVTX baseline logs and runs your rules against them to surface false positives. Requires `jq`, `wget`, and `tar`:

   ```bash
   bash tests/check-baseline-local.sh
   ```

   3.5. **Regression tests** *(optional, only if you added regression test files to your rule)* - rules with regression test can include a `regression_tests_path` field pointing to EVTX-based test data. To validate the file structure and mappings without any extra tooling:

   ```bash
   python tests/regression_tests_runner.py \
     --rules-paths rules/ rules-emerging-threats/ rules-threat-hunting/ \
     --validate-only
   ```

   To also run the tests against EVTX files, you first need to download the [`evtx-sigma-checker`](https://github.com/NextronSystems/evtx-baseline) binary according to your operating-system:

   ```bash
   python tests/regression_tests_runner.py \
     --rules-paths rules/ rules-emerging-threats/ rules-threat-hunting/ \
     --evtx-checker /path/to/evtx-sigma-checker \
     --thor-config tests/thor.yml
   ```

4. Once the test is successful, commit the changes to your branch:

```bash
git add .
git commit -m "Your commit message"
```

5. Push your changes to your fork:

```bash
git push origin your-feature-branch
```

6. Create a new Pull Request (PR) against the upstream repository:

* Go to the [Sigma repository](https://github.com/SigmaHQ/sigma) on GitHub
* Click the "New Pull Request" button
* Choose your fork and your feature branch
* Add a clear and descriptive title and a detailed description of your changes
* Submit the Pull Request

## 📚 Adding or Updating Detection Rules

Before writing a new rule, take these steps to align with the project's conventions and avoid duplication:

1. **Review recently merged PRs** - Browse [merged pull requests](https://github.com/SigmaHQ/sigma/pulls?q=is%3Apr+is%3Amerged) to see how rules are structured, titled, and reviewed. Pay attention to reviewer feedback, as it reflects the quality bar the project expects.

2. **Search for related rules in the repository** - Look for existing rules that cover the same log source, technique, or behavior. This helps you understand the established field naming, filter patterns, and detection logic already in use, and ensures you are not duplicating an existing rule.

   ```bash
   grep -r "your_keyword" rules/
   ```

   Prefer a web-based search? You have several options:
   - [GitHub Code Search](https://github.com/search?q=repo%3ASigmaHQ%2Fsigma&type=code) - search across the repository directly on GitHub
   - [grep.app](https://grep.app/search?f.repo=SigmaHQ%2Fsigma&f.repo.pattern=sigmahq&q=your_keyword) - fast regex search across the repo
   - [Sigma Search Engine](https://sigmasearchengine.com/) - purpose-built search across the entire Sigma rule set

   For example, if you are writing a rule that targets the Windows `process_creation` log source, browsing existing rules for that log source - using any of the above or directly in the [rules/windows/process_creation](./rules/windows/process_creation) directory - is a good way to understand the patterns and conventions already established.

To update or contribute a new rule please make sure to follow the guidelines in the [SigmaHQ conventions documents](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq). Consider installing the [VsCode Sigma Extension](https://marketplace.visualstudio.com/items?itemName=humpalum.sigma) for auto completion and quality of life features.

Thank you for contributing to Sigma! 🧙‍♂️
