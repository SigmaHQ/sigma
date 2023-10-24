# 3CX Supply Chain Attack

## Summary

On March 29, 2023 CrowdStrike detected malicious activity, originating from a legitimate, signed binary called 3CXDesktopApp. The binary is part of a softphone system developed by 3CX.
The observed malicious activity consisted of beaconing to infrastructure controlled by the actors, leading to the deployment of second-stage payloads and in a few cases direct on-keyboard activity from the attackers.

You can find more information on the threat in the following articles:

- [CrowdStrike Falcon Platform Detects and Prevents Active Intrusion Campaign Targeting 3CXDesktopApp Customers - By Crowdstrike](https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/)
- [3CX Supply Chain Compromise Leads to ICONIC Incident - By Volexity](https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/)
- [3CX VoIP Software Compromise & Supply Chain Threats - By Huntress](https://www.huntress.com/blog/3cx-voip-software-compromise-supply-chain-threats)
- [Using THOR Lite to scan for indicators of Lazarus activity related to the 3CX compromise - By Nextron Systems](https://www.nextron-systems.com/2023/03/31/using-thor-lite-to-scan-for-indicators-of-lazarus-activity-related-to-the-3cx-compromise/)
- [Not just an infostealer: Gopuram backdoor deployed through 3CX supply chain attack - By Kaspersky](https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/)
- [Elastic users protected from SUDDENICON’s supply chain attack - By Elastic](https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack)

## Rules

- [Potential Compromised 3CXDesktopApp Beaconing Activity - DNS](./dns_query_win_malware_3cx_compromise.yml)
- [Malicious DLL Load By Compromised 3CXDesktopApp](./image_load_malware_3cx_compromise_susp_dll.yml)
- [Potential Compromised 3CXDesktopApp Beaconing Activity - Netcon](./net_connection_win_malware_3cx_compromise_beaconing_activity.yml)
- [Potential Compromised 3CXDesktopApp Execution](./proc_creation_win_malware_3cx_compromise_execution.yml)
- [Potential Suspicious Child Process Of 3CXDesktopApp](./proc_creation_win_malware_3cx_compromise_susp_children.yml)
- [Potential Compromised 3CXDesktopApp Update Activity](./proc_creation_win_malware_3cx_compromise_susp_update.yml)
- [Potential Compromised 3CXDesktopApp Beaconing Activity - Proxy](./proxy_malware_3cx_compromise_c2_beacon_activity.yml)
- [Potential Compromised 3CXDesktopApp ICO C2 File Download](./proxy_malware_3cx_compromise_susp_ico_requests.yml)
