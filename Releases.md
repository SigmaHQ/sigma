This following document describes the different types of rule packages provided with every release.

## Package Introduction

The rule packages provided with every release are split based on the [status](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#status-optional), [level](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#level) and [type](https://medium.com/sigma-hq/sigma-rule-repository-enhancements-new-folder-structure-rule-types-30adb70f5e10) of a sigma rule.

There are currently 3 main rule types provided in the sigma repository:

- **core/generic**: Rules that match on attacker techniques. These rules are timeless and often match on new threats.
- **emerging-threats/ET**: Rules that match on patterns of specific threat actors or exploits. High signal to noise ratio but will decrease in relevance over time.
- **threat-hunting/TH**: Rules that should not be run for alerting but are interesting in giving detection ideas or hunt for suspicious activity inside an environment.

### Package Overview

name | status | level | type
--- | --- | --- | ---
[Core (Default)](#core-rules) | testing, stable | high, critical | core
[Core+ (Rule Review needed)](#core-rules-1) | testing, stable | medium, high, critical | core
[Core++ (Experimental)](#core-rules-2) | experimental, testing, stable | medium, high, critical | core
[Emerging Threats AddOn Rules](#et-emerging-threats-addon-rules) | experimental, testing, stable | medium, high, critical | emerging threats
[All rules](#all-rules) | experimental, testing, stable | medium, high, critical | core, emerging threats

If you are new, best start with the `Core` Sigma package. It includes high quality rules of high confidence and relevance and should not produce many false positives.

If your setup is working fine, you can add the `emerging threats` rules and start thinking about upgrading to `Core+` rules. If that is not enough and you like the pain, use the "all" rules package.

### Defined Package

#### Core Rules

The `Core` Sigma package includes high quality rules of high confidence and relevance and should not produce many false positives.

The selected rules are of level `high` or `critical`, which means matches are of high or critical importance. The rule status is `testing` or `stable`, which means the rule is at least of an age of half a year and no false positives were reported on it.

The type is `core`, meaning the rules will match on attacker technique and generic suspicious or malicious behavior.

#### Core+ Rules

The plus in the `Core+` Sigma package stands for the addition of `medium` level rules. Those rules most often need additional tuning as certain applications, legitimate user behavior or scripts of an organization might be matched. Not every `medium` level rule is useful in every organization.

#### Core++ Rules

The `Core++` package additionally includes the rules of `experimental` status. These rules are bleeding edge. They are validated against the Goodlog tests available to the SigmaHQ project and reviewed by multiple detection engineers. Other than that they are pretty much untested at first. Use these if you want to be able to detect threats as early as possible at the cost of managing a higher threshold of false positives.

Please report any false positives you find in the wild via our [github issue tracker](https://github.com/SigmaHQ/sigma/issues/new?assignees=&labels=False-Positive&projects=&template=false_positive_report.yml). After a grace period all `experimental` rules will eventually be promoted to status `test`.

### Package AddOn's

#### ET (Emerging Threats) AddOn Rules

The `ET AddOn` Sigma package contains all of the `emerging threats` rules. These rules have a low false positive rate so that it already contains rules of status `experimental`. These rules target specific threats and are especially useful for current threats where maybe not much information is yet available. So we want to get them to you as fast as possible. The package is an `AddOn` so you can use it on top of whichever `Core` package is most useful to you.

### All Rules

> **Note**
>
> This package doesn't contain all rules

This package includes all rules from level `medium` with a status of `experimental` and upwards including the `emerging threats` rules. Some heavy tuning is required when using this package.

You'll notice that rules of level `low` and some other are omitted even from this the `All Rules` package. We do not recommend using any other types of rules to generate alerts except for those provided in these packages.

### Create Your Own Custom Rule Package

Releases are tagged using the format `r<ISO 8601 date>` (e.g. `r2023-12-24`).

You can checkout any release version and create your own package using the [sigma-package-release](tests/sigma-package-release.py) script. Define the `status`, `level` and `type` of rules and the script generates a ZIP archive containing only those rules.

e.g.

```bash
# python3 tests/sigma-package-release.py --min-status testing --levels high critical --types generic --outfile Sigma-custom.zip
```

You can either give `level` and `status` as a space separated list or using a minimum value. See `--help` for all options
