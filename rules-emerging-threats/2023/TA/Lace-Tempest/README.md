# Lace Tempest SysAid CVE-2023-47246 Exploitation

## Summary

A zero-day vulnerability in the SysAid on-premises software was exploited by DEV-0950 (Lace Tempest). Where the threat actor uploaded a WAR archive containing a WebShell and other payloads into the webroot of the SysAid Tomcat web service. The WebShell provided the attacker with unauthorized access and control over the affected system. Subsequently, the attacker utilized a PowerShell script, deployed through the WebShell, to execute a malware loader named user.exe on the compromised host, which was used to load the GraceWire trojan

You can find more information on the threat in the following articles:

- [SysAid On-Prem Software CVE-2023-47246 Vulnerability](https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification)

## Rules

- [Lace Tempest File Indicators](./file_event_win_apt_lace_tempest_indicators.yml)
- [Lace Tempest PowerShell Evidence Eraser](./posh_ps_apt_lace_tempest_eraser_script.yml)
- [Lace Tempest PowerShell Launcher](./posh_ps_apt_lace_tempest_malware_launcher.yml)
- [Lace Tempest Cobalt Strike Download](./proc_creation_win_apt_lace_tempest_cobalt_strike_download.yml)
- [Lace Tempest Malware Loader Execution](./proc_creation_win_apt_lace_tempest_loader_execution.yml)
