## Sigma Release packages

If you are new, best start with the `Core` Sigma package. It includes high quality rules of high confidence and relevance and should not produce many false positives.

If your setup is working fine, you can add the `emerging threats` rules and start thinking about upgrading to `Core+` rules. If that is not enough and you like the pain, use the "all" rules package.

### Package Introduction

To understand how the packages are structured, you need to understand 3 attributes of Sigma rules. The `status`, `level` and `type` of the rule.

#### Status

See the [specification](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#status-optional) for more information.

#### Level

See the [specification](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#level) for more information.

#### Type

There are currently 3 types of rules:

- **core/generic**: Rules that match on attacker technique. Those rules are timeless and even often match on new threats
- **emerging-threats/et**: Rules that match on patterns of specific threat actors or exploits. High signal to noise ratio but will decrease in relevance over time
- **threat-hunting/th**: Rules that should not be run for alerting but are interesting in giving detection ideas or hunt for suspicious activity inside an environment

### Defined Package

#### Core Rules

The `Core` Sigma package includes high quality rules of high confidence and relevance and should not produce many false positives.

The selected rules are of level high or critical, which means matches are of high or critical importance. The rule status is testing or stable, which today means the rule is at least of an age of half a year and no false positives were reported on it. The type is `core`, meaning the rules will match on attacker technique and generic suspicious or malicious behaviour.

#### Core+ Rules

The plus in the `Core+` Sigma package stands for the addition of `medium` level rules. Those rules most often need additional false positive tuning as certain applications, legitimate user behaviour or scripts of an organisation might be matched. Not every `medium` level rule is useful in every organisation.

#### Core++ Rules

The additional plus in the `Core++` Sigma package stands for `experimental` level rules. These rules are bleeding edge. They are validated against the Goodlog tests available to the SigmaHQ project and reviewed by multiple detection engineers. Other than that they are pretty much untested at first. Use these if you want to be able to detect threats as early as possible and being willing to pay the price in managing more-than-usual false positives.

Please be so kind to [report any false positives](https://github.com/SigmaHQ/sigma/issues/new?assignees=&labels=False-Positive&projects=&template=false_positive_report.yml) you find. After a grace period all `experimental` rules will eventually be promoted to status `test`.

#### ET (Emerging Threats) AddOn Rules

The `ET AddOn` Sigma package contains all `emerging threats` rules. These rules have a low false positive rate so that it already contains rules of status `experimental`. These rules target specific threats and are especially useful for current threats where maybe not much information is yet available. So we want to get them to you as fast as possible. The package is an `AddOn` so you can use it on top of whichever `Core` package is most useful to you.

#### All Rules

*This package doesn't contain all rules

But it is all rules you ever **WANT** to use for alerting. It includes `medium` level rules of status `experimental` and upwards including the `emerging threats` rules. So get ready for some tuning. But to reiterate: This is the maximum configuration of rules which we expect you to use for generating alerts. If you use any other rule, don't complain.

### Table Overview

name | status | level | type
--- | --- | --- | ---
Core (Default) | testing, stable | high, critical | core
Core+ (Rule Review needed) | testing, stable | medium, high, critical | core
Core++ (Experimental) | experimental, testing, stable | medium, high, critical | core
Emerging Threats AddOn Rules | experimental, testing, stable | medium, high, critical | emerging threats
All rules | experimental, testing, stable | medium, high, critical | core, emerging threats

### Create Your Own Custom Package

Releases are tagged using the format `r<ISO 8601 date>` (e.g. `r2023-12-24`).

You can checkout any release version and create your own package using the [sigma-package-release](tests/sigma-package-release.py) script. Define the `status`, `level` and `type` of rules and the script generates a ZIP archive containing only those rules.

e.g.

```
# python3 tests/sigma-package-release.py --min-status testing --levels high critical --types generic --outfile Sigma-custom.zip
```
(You can either give `level` and `status` as a space separated list or using a minimum value. See `--help` for all options)