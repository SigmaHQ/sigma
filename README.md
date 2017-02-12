![sigma_logo](./images/Sigma_0.3.png)

# Sigma
Generic Signature Format for SIEM Systems

# What is Sigma?

Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.

![sigma_description](./images/Sigma-description.png)

This repository contains:

* Sigma rule specification in the [Wiki](https://github.com/Neo23x0/sigma/wiki/Specification)
* Open repository for sigma signatures in the ```./rules```subfolder
* Collection of converters that generate searches/queries for different SIEM systems [Pending]

# Slides

See the first slide deck that I prepared for a private conference in mid January 2017.

[Sigma - Make Security Monitoring Great Again](https://www.slideshare.net/secret/gvgxeXoKblXRcA)


# Specification

The specifications can be found in the [Wiki](https://github.com/Neo23x0/sigma/wiki/Specification). 

The current specification can be seen as a proposal. Feedback is requested.

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

# Next Steps 

* Creation of a reasonable set of sample rules
* Release of the first rule converters for Elastic Search and Splunk
* Integration of feedback into the rule specifications
* Collecting rule input from fellow researchers and analysts
* Attempts to convince others to use the rule format in their reports, threat feeds, blog posts, threat sharing platforms
