[![sigma build status](https://github.com/SigmaHQ/sigma/actions/workflows/sigma-test.yml/badge.svg?branch=master)](https://github.com/SigmaHQ/sigma/actions?query=branch%3Amaster)

![sigma_logo](./images/Sigma_0.3.png)

# Sigma

Generic Signature Format for SIEM Systems

# What is Sigma

Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.

Sigma is for log files what [Snort](https://www.snort.org/) is for network traffic and [YARA](https://github.com/VirusTotal/yara) is for files.

This repository contains:

1. Sigma rule specification in the [Sigma-Specification](https://github.com/SigmaHQ/sigma-specification) repository
2. Open repository for sigma signatures in the `./rules` subfolder

![sigma_description](./images/Sigma-description.png)

## Hack.lu 2017 Talk

[![Sigma - Generic Signatures for Log Events](https://preview.ibb.co/cMCigR/Screen_Shot_2017_10_18_at_15_47_15.png)](https://www.youtube.com/watch?v=OheVuE9Ifhs "Sigma - Generic Signatures for Log Events")

## SANS Webcast on MITRE ATT&CK® and Sigma

The SANS webcast on Sigma contains a very good 20 min introduction to the project by John Hubbart from minute 39 onward. (SANS account required; registration is free)

[MITRE ATT&CK® and Sigma Alerting Webcast Recording](https://www.sans.org/webcasts/mitre-att-ck-sigma-alerting-110010 "MITRE ATT&CK® and Sigma Alerting")

# Use Cases

* Describe your detection method in Sigma to make it shareable
* Write your SIEM searches in Sigma to avoid a vendor lock-in
* Share the signature in the appendix of your analysis along with IOCs and YARA rules
* Share the signature in threat intel communities - e.g. via MISP
* Provide Sigma signatures for malicious behaviour in your own application

# Why Sigma

Today, everyone collects log data for analysis. People start working on their own, processing numerous white papers, blog posts and log analysis guidelines, extracting the necessary information and build their own searches and dashboard. Some of their searches and correlations are great and very useful but they lack a standardized format in which they can share their work with others.

Others provide excellent analyses, include IOCs and YARA rules to detect the malicious files and network connections, but have no way to describe a specific or generic detection method in log events. Sigma is meant to be an open standard in which such detection mechanisms can be defined, shared and collected in order to improve the detection capabilities for everyone.

## Slides

See the first slide deck that I prepared for a private conference in mid January 2017.

[Sigma - Make Security Monitoring Great Again](https://www.slideshare.net/secret/gvgxeXoKblXRcA)

# Specification

The specifications can be found in the [Sigma-Specification](https://github.com/SigmaHQ/sigma-specification) repository.

The current specification is a proposal. Feedback is requested.

# Getting Started

## Rule Creation

Florian wrote a short [rule creation tutorial](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/) that can help you getting started. Use the [Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide) in our Wiki for a clear guidance on how to populate the various field in Sigma rules.

## Rule Usage

* Use [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) to convert your rules into queries.
* Use [pySigma](https://github.com/SigmaHQ/pySigma) to integrate Sigma in your own toolchain or product.
* Check out the [legacy sigmatools and sigmac](https://github.com/SigmaHQ/legacy-sigmatools) if your target query
  language is not yet supported by the new toolchain. Please be aware that the legacy sigmatools are not maintained
  anymore and some of the backends don't generate correct queries.

# Examples

Windows 'Security' Eventlog: Access to LSASS Process with Certain Access Mask / Object Type (experimental)
![sigma_rule example2](./images/Sigma_rule_example2.png)

Sysmon: Remote Thread Creation in LSASS Process
![sigma_rule example1](./images/Sigma_rule_example1.png)

Web Server Access Logs: Web Shell Detection
![sigma_rule example3](./images/Sigma_rule_example3.png)

Sysmon: Web Shell Detection
![sigma_rule example4](./images/Sigma_rule_example4.png)

Windows 'Security' Eventlog: Suspicious Number of Failed Logons from a Single Source Workstation
![sigma_rule example5](./images/Sigma_rule_example5.png)

# Projects or Products that use Sigma

* [MISP](http://www.misp-project.org/2017/03/26/MISP.2.4.70.released.html) (since version 2.4.70, March 2017)
* [Atomic Threat Coverage](https://github.com/atc-project/atomic-threat-coverage) (since December 2018)
* [SOC Prime - Sigma Rule Editor](https://tdm.socprime.com/sigma/)
* [uncoder.io](https://uncoder.io/) - Online Translator for SIEM Searches
* [THOR](https://www.nextron-systems.com/2018/06/28/spark-applies-sigma-rules-in-eventlog-scan/) - Scan with Sigma rules on endpoints
* [Joe Sandbox](https://www.joesecurity.org/)
* [ypsilon](https://github.com/P4T12ICK/ypsilon) - Automated Use Case Testing
* [RANK VASA](https://globenewswire.com/news-release/2019/03/04/1745907/0/en/RANK-Software-to-Help-MSSPs-Scale-Cybersecurity-Offerings.html)
* [TA-Sigma-Searches](https://github.com/dstaulcu/TA-Sigma-Searches) (Splunk App)
* [TimeSketch](https://github.com/google/timesketch/commit/0c6c4b65a6c0f2051d074e87bbb2da2424fa6c35)
* [SIΣGMA](https://github.com/3CORESec/SIEGMA) - SIEM consumable generator that utilizes Sigma for query conversion
* [Aurora Agent](https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/)
* [Confluent Sigma](https://github.com/confluentinc/cyber/tree/master/confluent-sigma)
* [SEKOIA.IO](https://www.sekoia.io) - XDR supporting Sigma and Sigma Correlation rules languages

Sigma is available in some Linux distribution repositories:

[![Packaging status](https://repology.org/badge/vertical-allrepos/sigma.svg)](https://repology.org/project/sigma/versions)

# Contribution

If you want to contribute, you are more then welcome. There are numerous ways to help this project.

## Use it and provide feedback

If you use it, let us know what works and what does not work.

E.g.

* Tell us about false positives (issues section)
* Try to provide an improved rule (new filter) via [pull request](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository) on that rule

To help you, we may ask you for a return.
The PR will be tagged with "Author Input Required", however without a response it will have to be closed after 1 month of inactivity.

## Work on open issues

The github issue tracker is a good place to start tackling some issues others raised to the project. It could be as easy as a review of the documentation.

## Provide Backends / Backend Features / Bugfixes

Please don't provide backends for the old code base (sigmac) anymore. Please use the new [pySigma](https://github.com/SigmaHQ/pySigma). We are working on a documentation on how to write new backends for that new code base. An example backend for Splunk can be found [here](https://github.com/SigmaHQ/pySigma-backend-splunk).

## Spread the word

Last but not least, the more people use Sigma, the better, so help promote it by sharing it via social media. If you are using it, consider giving a talk about your journey and tell us about it.

# Licenses

The content of this repository is released under the following licenses:

* The [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) and the Sigma logo are public domain
* The rules contained in the [SigmaHQ repository](https://github.com/SigmaHQ) are released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)

# Credits

This is a private project mainly developed by Florian Roth and Thomas Patzke with feedback from many fellow analysts and friends. Rules are our own or have been drived from blog posts, tweets or other public sources that are referenced in the rules.

# Info Graphic

## Overview
![sigmac_info_graphic](./images/sigma_infographic_lq.png)

## Coverage Illustration
![sigmac_coverage](./images/Sigma_Coverage.png)
