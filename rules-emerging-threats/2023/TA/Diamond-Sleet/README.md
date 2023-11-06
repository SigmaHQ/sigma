# Diamond Sleet APT

## Summary

Diamond Sleet (ZINC) is a North Korean nation-state threat actor that prioritizes espionage, data theft, financial gain, and network destruction. The actor typically targets media, IT services, and defense-related entities around the world.

You can find more information on the threat in the following articles:

- [Multiple North Korean threat actors exploiting the TeamCity CVE-2023-42793 vulnerability](https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/)

## Rules

- [Diamond Sleet APT DNS Communication Indicators](./dns_query_win_apt_diamond_steel_indicators.yml)
- [Diamond Sleet APT File Creation Indicators](./file_event_win_apt_diamond_sleet_indicators.yml)
- [Diamond Sleet APT DLL Sideloading Indicators](./image_load_apt_diamond_sleet_side_load.yml)
- [Diamond Sleet APT Process Activity Indicators](./proc_creation_win_apt_diamond_sleet_indicators.yml)
- [Diamond Sleet APT Scheduled Task Creation - Registry](./registry_event_apt_diamond_sleet_scheduled_task.yml)
- [Diamond Sleet APT Scheduled Task Creation](./win_security_apt_diamond_sleet_scheduled_task.yml)
