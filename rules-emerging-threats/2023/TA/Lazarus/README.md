# Lazarus APT

Last Updated: 18/10/2023

## Summary

ESET researchers have uncovered a Lazarus attack against an aerospace company in Spain, where the group deployed several tools, most notably a publicly undocumented backdoor that ESET is naming LightlessCan. Lazarus operators obtained initial access to the company’s network last year after a successful spearphishing campaign, masquerading as a recruiter for Meta – the company behind Facebook, Instagram, and WhatsApp. Four different execution chains were identified, delivering three types of payloads via DLL side-loading.

You can find more information on the threat in the following articles:

- [Lazarus luring employees with trojanized coding challenges: The case of a Spanish aerospace company](https://www.welivesecurity.com/en/eset-research/lazarus-luring-employees-trojanized-coding-challenges-case-spanish-aerospace-company/)
- [Lazarus hackers breach aerospace firm with new LightlessCan malware](https://www.bleepingcomputer.com/news/security/lazarus-hackers-breach-aerospace-firm-with-new-lightlesscan-malware/)

## Rules

- [Lazarus APT DLL Sideloading Activity](./image_load_apt_lazarus_side_load_activity.yml)
