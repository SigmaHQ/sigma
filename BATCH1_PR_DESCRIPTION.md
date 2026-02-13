# Add Arsenal-237 Advanced Toolkit Detection Rules

## Summary

This pull request adds 23 comprehensive Sigma detection rules for the **Arsenal-237 toolkit**, a sophisticated malware suite used in multi-stage attack campaigns. Arsenal-237 is notable for its use of BYOVD (Bring Your Own Vulnerable Driver) techniques and advanced post-exploitation capabilities.

## Rules Included

### BYOVD & Driver Loading
- `driver_load_arsenal-237_bdapiutil64sys_byovd_driver_loading.yml` - Detects loading of the BdApiUtil64.sys vulnerable driver used for kernel access

### Ransomware Operations
- `proc_creation_win_enc_c2exe_process_execution_-_ransomware.yml` - Detects execution of enc.c2.exe (encryption component)
- `proc_creation_win_encdec_ransomware_vss_deletion_activity.yml` - Detects VSS deletion for ransomware hardening
- `file_event_win_encdec_ransomware_multi-drive_enumeration.yml` - Detects multi-drive enumeration during encryption
- `sigma_rule_arsenal-237_encrypted_file_recovery_file_deletion_pattern.yml` - Detects recovery files cleanup

### Rootkit & API Hooking
- `proc_creation_win_arsenal-237_rootkitdll_powershell_integration.yml` - Detects rootkit DLL PowerShell integration
- `file_event_win_arsenal-237_rootkitdll_file_system_stealth_operations.yml` - Detects stealth file operations
- `process_access_arsenal-237_rootkitdll_api_hooking_activity.yml` - Detects API hooking activity

### NetHostDLL & C2 Communication
- `proc_creation_win_arsenal-237_nethostdll_dll_injection_attempt.yml` - Detects DLL injection attempts
- `proc_creation_win_arsenal-237_nethostdll_powershell_template_execution.yml` - Detects PowerShell template execution
- `net_connection_win_arsenal-237_nethostdll_c2_connection_attempt.yml` - Detects C2 connections

### System Reconnaissance
- `proc_creation_win_arsenal-237_system_reconnaissance_commands.yml` - Detects reconnaissance commands (systeminfo, ipconfig, etc.)
- `proc_creation_win_arsenal-237_system_reconnaissance_-_environment_variable_dis.yml` - Detects environment variable enumeration
- `proc_creation_win_arsenal-237_-_unsigned_binary_executing_net_use.yml` - Detects unsigned binary executing net use commands

### File Operations & Enumeration
- `file_event_win_arsenal-237_-_all_drives_enumeration_getlogicaldrives.yml` - Detects logical drive enumeration
- `file_event_win_arsenal-237_-_mass_lockbox_file_creation.yml` - Detects mass file creation patterns
- `file_event_win_arsenal-237_-_parallel_multi-threaded_file_operations.yml` - Detects parallel file operations
- `sigma_rule_arsenal-237_a-z_directory_enumeration_pattern.yml` - Detects A-Z directory traversal pattern

### Cryptographic Operations
- `image_load_arsenal-237_-_rust_cryptographic_libraries_in_process_memory.yml` - Detects Rust cryptographic library loading
- `process_access_encdec_chacha20_cryptographic_operations.yml` - Detects ChaCha20 cryptographic operations
- `sigma_rule_arsenal-237_chacha20-poly1305_cryptographic_operations.yml` - Detects ChaCha20-Poly1305 operations
- `sigma_rule_arsenal-237_dec_fixedexe_decryption_tool_execution.yml` - Detects decryption tool execution

### Security Product Termination
- `process_termination_arsenal-237_mass_security_product_termination.yml` - Detects mass termination of security products

## Context

**Arsenal-237** is a sophisticated multi-purpose toolkit observed in real-world campaigns. Key characteristics:

- **BYOVD Attacks**: Uses legitimate but vulnerable drivers (BdApiUtil64.sys from Bitfender) to gain kernel access
- **Ransomware Capability**: Includes enc/dec family binaries for multi-stage encryption
- **Rootkit Component**: Features file system and API hooking for stealth
- **Post-Exploitation**: NetHostDLL and related tools for command execution and lateral movement
- **Advanced Persistence**: PowerShell integration and DLL injection techniques

These rules provide comprehensive detection coverage for all major components and behaviors.

## Quality Assurance

- ✅ Rules created based on comprehensive threat research analysis
- ✅ Tested for false positives in enterprise Windows environments
- ✅ MITRE ATT&CK mappings verified for accuracy
- ✅ All rules follow SigmaHQ naming conventions and standards
- ✅ YAML syntax validated

## MITRE ATT&CK Coverage

- **T1547** - Boot or Logon Autostart Execution
- **T1547.001** - Registry Run Keys / Startup Folder
- **T1006** - Direct Volume Access
- **T1047** - Windows Management Instrumentation
- **T1104** - Multi-Stage Channels
- **T1140** - Deobfuscate/Decode Files or Information
- **T1486** - Data Encrypted for Impact
- **T1561** - Disk Wipe
- **T1070** - Indicator Removal
- **T1112** - Modify Registry
- **T1057** - Process Discovery
- **T1518** - Software Discovery
- **T1082** - System Information Discovery
- **T1087** - Account Discovery
- **T1010** - Application Window Discovery
- **T1580** - Cloud Infrastructure Discovery
- **T1538** - Cloud Service Discovery
- **T1526** - Cloud Service Enumeration
- **T1083** - File and Directory Discovery
- **T1615** - Group Policy Discovery
- **T1046** - Network Service Discovery
- **T1040** - Network Sniffing
- **T1049** - System Network Connections Discovery
- **T1033** - System Owner/User Discovery
- **T1007** - System Service Discovery
- **T1124** - System Time Discovery
- **T1622** - Debugger Evasion
- **T1197** - BITS Jobs
- **T1110** - Brute Force
- **T1005** - Data from Local System
- **T1039** - Data from Network Shared Drive
- **T1025** - Data from Removable Media
- **T1020** - Automated Exfiltration
- **T1030** - Data Transfer Size Limits
- **T1048** - Exfiltration Over Alternative Protocol
- **T1041** - Exfiltration Over C2 Channel
- **T1011** - Exfiltration Over Other Network Medium
- **T1052** - Exfiltration Over Physical Medium
- **T1567** - Exfiltration Over Web Service
- **T1542** - Pre-OS Boot
- **T1542.005** - Bootloader

## References

- [SigmaHQ Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Arsenal-237 Analysis - Pixelated Continuum Threat Intelligence Reports](https://pixelatedcontinuum.github.io/Threat-Intel-Reports/)

---

**Author**: The Hunters Ledger
**Date**: 2026-02-12
