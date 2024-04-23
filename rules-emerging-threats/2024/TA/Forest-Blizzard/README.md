# Forest Blizzard’s Exploiting CVE-2022-38028

## Summary

Microsoft Threat Intelligence published results of their longstanding investigation into activity by the Russian-based threat actor Forest Blizzard (STRONTIUM) using a custom tool to elevate privileges and steal credentials in compromised networks. Since at least June 2020 and possibly as early as April 2019, Forest Blizzard has used the tool, which we refer to as GooseEgg, to exploit the CVE-2022-38028 vulnerability in Windows Print Spooler service by modifying a JavaScript constraints file and executing it with SYSTEM-level permissions. 

You can find more information on the threat in the following articles:

- [Analyzing Forest Blizzard’s custom post-compromise tool for exploiting CVE-2022-38028 to obtain credentials](https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/)

## Rules

- [Forest Blizzard APT - File Creation Activity](./file_event_win_apt_forest_blizzard_activity.yml)
- [Forest Blizzard APT - JavaScript Constrained File Creation](./file_event_win_apt_forest_blizzard_constrained_js.yml)
- [Forest Blizzard APT - Process Creation Activity](./proc_creation_win_apt_forest_blizzard_activity.yml)
- [Forest Blizzard APT - Custom Protocol Handler DLL Registry Set](./registry_set_apt_forest_blizzard_custom_protocol_handler.yml)
- [Forest Blizzard APT - Custom Protocol Handler Creation](./registry_set_apt_forest_blizzard_custom_protocol_handler_dll.yml)
