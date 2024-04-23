# Forest Blizzard’s Exploiting CVE-2022-38028

## Summary

You can find more information on the threat in the following articles:

- [Analyzing Forest Blizzard’s custom post-compromise tool for exploiting CVE-2022-38028 to obtain credentials](https://www.microsoft.com/en-us/security/blog/2024/04/22/analyzing-forest-blizzards-custom-post-compromise-tool-for-exploiting-cve-2022-38028-to-obtain-credentials/)

## Rules

- [Forest Blizzard APT - File Creation Activity](./file_event_win_apt_forest_blizzard_activity.yml)
- [Forest Blizzard APT - JavaScript Constrained File Creation](./file_event_win_apt_forest_blizzard_constrained_js.yml)
- [Forest Blizzard APT - Process Creation Activity](./proc_cration_win_apt_forest_blizzard_activity.yml)
- [Forest Blizzard APT - Custom Protocol Handler DLL Registry Set](./registry_set_apt_forest_blizzard_custom_protocol_handler.yml)
- [Forest Blizzard APT - Custom Protocol Handler Creation](./registry_set_apt_forest_blizzard_custom_protocol_handler_dll.yml)
