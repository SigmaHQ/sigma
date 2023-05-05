# FIN7 Targets Veeam Backup Servers

## Summary

WithSecure Labs reported on the 26th of April 2023 on attacks their intelligence teams identified in late March 2023 against internet-facing servers running Veeam Backup & Replication software.

You can find more information on the threat in the following articles:

- [FIN7 tradecraft seen in attacks against Veeam backup servers](https://labs.withsecure.com/publications/fin7-target-veeam-servers)

## Rules

- [Potential APT FIN7 Related PowerShell Script Created](./file_event_win_apt_fin7_powershell_scripts_naming_convention.yml)
- [Potential APT FIN7 POWERHOLD Execution](./posh_ps_apt_fin7_powerhold.yml)
- [Potential POWERTRASH Script Execution](./posh_ps_apt_fin7_powertrash_execution.yml)
- [Potential APT FIN7 Reconnaissance/POWERTRASH Related Activity](./proc_creation_win_apt_fin7_powertrash_lateral_movement.yml)
