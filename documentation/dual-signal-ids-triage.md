# Dual-signal IDS triage (SnortML ≠ signature TP)

Sigma rules under `rules/network/firewall/` that encode composite confidence for
Cisco Secure Firewall / Snort-family telemetry:

| Rule | Intent |
|---|---|
| [SnortML High Confidence ML-Only Alert](../rules/network/firewall/net_firewall_snortml_gid411_high.yml) | GID 411 → escalate / corroborate — **not** auto-contain |
| [IDS Signature High Priority Classification](../rules/network/firewall/net_firewall_ids_signature_high_priority.yml) | Classic signature classifications → stronger TP candidate |
| [IDS Signature And High EVE Corroboration](../rules/network/firewall/net_firewall_ids_signature_and_eve_corroboration.yml) | Signature + high EVE → corroborated path |

## Hard rule

**ML probability is never equivalent to a signature true positive.**

Automation and agent harnesses that call containment tools should deny or
HITL-interrupt ML-only highs and prefer corroborated signature paths.

## Production consumer

Aegis Decision Fabric consumes this disposition envelope for gated remediation:
https://github.com/AAH20/aegis-decision-fabric

Secure Firewall + Splunk environments under contract (Continuous Trust / paid pilot):
https://a2zsoc.com/consultation
