# service: security

ID: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64

## Content

<details>
    <summary>Details</summary>

- [service: security](#service-security)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Account Logon](#account-logon)
      - [Credential Validation](#credential-validation)
      - [Kerberos Authentication Service](#kerberos-authentication-service)
      - [Kerberos Service Ticket Operations](#kerberos-service-ticket-operations)
      - [Other Account Logon Events](#other-account-logon-events)
    - [Account Management](#account-management)
      - [Application Group Management](#application-group-management)
      - [Computer Account Management](#computer-account-management)
      - [Distribution Group Management](#distribution-group-management)
      - [Other Account Management Events](#other-account-management-events)
      - [Security Group Management](#security-group-management)
      - [User Account Management](#user-account-management)
    - [Detailed Tracking](#detailed-tracking)
      - [DPAPI Activity](#dpapi-activity)
      - [PNP Activity](#pnp-activity)
      - [Process Creation](#process-creation)
      - [Process Termination](#process-termination)
      - [RPC Events](#rpc-events)
      - [Token Right Adjusted](#token-right-adjusted)
    - [DS Access](#ds-access)
      - [Detailed Directory Service Replication](#detailed-directory-service-replication)
      - [Directory Service Access](#directory-service-access)
      - [Directory Service Changes](#directory-service-changes)
      - [Directory Service Replication](#directory-service-replication)
    - [Logon/Logoff](#logonlogoff)
      - [Account Lockout](#account-lockout)
      - [User/Device Claims](#userdevice-claims)
      - [Group Membership](#group-membership)
      - [IPsec Extended Mode](#ipsec-extended-mode)
      - [IPsec Main Mode](#ipsec-main-mode)
      - [IPsec Quick Mode](#ipsec-quick-mode)
      - [Logoff](#logoff)
      - [Logon](#logon)
      - [Network Policy Server](#network-policy-server)
      - [Other Logon/Logoff Events](#other-logonlogoff-events)
      - [Special Logon](#special-logon)
    - [Object Access](#object-access)
      - [Application Generated](#application-generated)
      - [Certification Services](#certification-services)
      - [Detailed File Share](#detailed-file-share)
      - [File Share](#file-share)
      - [File System](#file-system)
      - [Filtering Platform Connection](#filtering-platform-connection)
      - [Filtering Platform Packet Drop](#filtering-platform-packet-drop)
      - [Handle Manipulation](#handle-manipulation)
      - [Kernel Object](#kernel-object)
      - [Other Object Access Events](#other-object-access-events)
      - [Registry](#registry)
      - [Removable Storage](#removable-storage)
      - [SAM](#sam)
      - [Central Access Policy Staging](#central-access-policy-staging)
    - [Policy Change](#policy-change)
      - [Audit Policy Change](#audit-policy-change)
      - [Authentication Policy Change](#authentication-policy-change)
      - [Authorization Policy Change](#authorization-policy-change)
      - [Filtering Platform Policy Change](#filtering-platform-policy-change)
      - [MPSSVC Rule-Level Policy Change](#mpssvc-rule-level-policy-change)
      - [Other Policy Change Events](#other-policy-change-events)
    - [Privilege Use](#privilege-use)
      - [Non Sensitive Privilege Use](#non-sensitive-privilege-use)
      - [Other Privilege Use Events](#other-privilege-use-events)
      - [Sensitive Privilege Use](#sensitive-privilege-use)
    - [System](#system)
      - [IPsec Driver](#ipsec-driver)
      - [Other System Events](#other-system-events)
      - [Security State Change](#security-state-change)
      - [Security System Extension](#security-system-extension)
      - [System Integrity](#system-integrity)
    - [Global Object Access Auditing](#global-object-access-auditing)
  - [Full Event(s) List](#full-events-list)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4624](#provider-microsoft-windows-security-auditing--eventid-4624)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4627](#provider-microsoft-windows-security-auditing--eventid-4627)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4663](#provider-microsoft-windows-security-auditing--eventid-4663)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4670](#provider-microsoft-windows-security-auditing--eventid-4670)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4672](#provider-microsoft-windows-security-auditing--eventid-4672)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4673](#provider-microsoft-windows-security-auditing--eventid-4673)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4688](#provider-microsoft-windows-security-auditing--eventid-4688)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4689](#provider-microsoft-windows-security-auditing--eventid-4689)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4702](#provider-microsoft-windows-security-auditing--eventid-4702)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4703](#provider-microsoft-windows-security-auditing--eventid-4703)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4957](#provider-microsoft-windows-security-auditing--eventid-4957)
    - [Provider: Microsoft Windows Security Auditing / EventID: 5447](#provider-microsoft-windows-security-auditing--eventid-5447)

</details>

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `security` service.

## Event Source(s)

```yml
Provider: Microsoft Windows Security Auditing
GUID: {54849625-5478-4994-a5ba-3e3b0328c30d}
Channel: Security
```

## Logging Setup

### Account Logon

#### Credential Validation

- Subcategory GUID: `{0CCE923F-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4774`
  - `4775`
  - `4776`
  - `4777`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Logon
                        - Audit Credential Validation
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-credential-validation)

#### Kerberos Authentication Service

- Subcategory GUID: `{0CCE9242-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High on Kerberos Key Distribution Center servers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4768`
  - `4771`
  - `4772`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Logon
                        - Audit Kerberos Authentication Service
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service)

#### Kerberos Service Ticket Operations

- Subcategory GUID: `{0CCE9240-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Very High on Kerberos Key Distribution Center servers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4769`
  - `4770`
  - `4773`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Logon
                        - Audit Kerberos Service Ticket Operations
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations)

#### Other Account Logon Events

- Subcategory GUID: `{0CCE9241-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - TBD

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Logon
                        - Audit Other Account Logon Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9241-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9241-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-account-logon-events)

### Account Management

#### Application Group Management

- Subcategory GUID: `{0CCE9239-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4783`
  - `4784`
  - `4785`
  - `4786`
  - `4787`
  - `4788`
  - `4789`
  - `4790`
  - `4791`
  - `4792`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit Application Group Management
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9239-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9239-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-application-group-management)

#### Computer Account Management

- Subcategory GUID: `{0CCE9236-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low on domain controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4741`
  - `4742`
  - `4743`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit Computer Account Management
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9236-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9236-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-computer-account-management)

#### Distribution Group Management

- Subcategory GUID: `{0CCE9238-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low on Domain Controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4749`
  - `4750`
  - `4751`
  - `4752`
  - `4753`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit Distribution Group Management
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9238-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9238-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-distribution-group-management)

#### Other Account Management Events

- Subcategory GUID: `{0CCE923A-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Typically Low on all types of computers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4782`
  - `4793`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit Other Account Management Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923A-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923A-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-account-management-events)

#### Security Group Management

- Subcategory GUID: `{0CCE9237-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4728`
  - `4731`
  - `4732`
  - `4733`
  - `4734`
  - `4735`
  - `4764`
  - `4799`
  - `4727`
  - `4737`
  - `4728`
  - `4729`
  - `4730`
  - `4754`
  - `4755`
  - `4756`
  - `4757`
  - `4758`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit Security Group Management
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management)

#### User Account Management

- Subcategory GUID: `{0CCE9235-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4720`
  - `4722`
  - `4723`
  - `4724`
  - `4725`
  - `4726`
  - `4738`
  - `4740`
  - `4765`
  - `4766`
  - `4767`
  - `4780`
  - `4781`
  - `4794`
  - `4798`
  - `5376`
  - `5377`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Account Management
                        - Audit User Account Management
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management)

### Detailed Tracking

#### DPAPI Activity

- Subcategory GUID: `{0CCE922D-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4692`
  - `4693`
  - `4694`
  - `4695`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit DPAPI Activity
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922D-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922D-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-dpapi-activity)

#### PNP Activity

- Subcategory GUID: `{0CCE9248-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Varies, depending on how the computer is used. Typically Low.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `6416`
  - `6419`
  - `6420`
  - `6421`
  - `6422`
  - `6423`
  - `6424`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit PNP Activity
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9248-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9248-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-pnp-activity)

#### Process Creation

- Subcategory GUID: `{0CCE922B-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4688`
  - `4696`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Process Creation
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)

#### Process Termination

- Subcategory GUID: `{0CCE922C-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low to Medium, depending on system usage.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4689`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Process Termination
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-termination)

#### RPC Events

- Subcategory GUID: `{0CCE922E-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `5712`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit RPC Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-rpc-events)

#### Token Right Adjusted

- Subcategory GUID: `{0CCE924A-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4703`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Token Right Adjusted
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-token-right-adjusted)

### DS Access

#### Detailed Directory Service Replication

- Subcategory GUID: `{0CCE923E-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `These events can create a very high volume of event data on domain controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4928`
  - `4929`
  - `4930`
  - `4931`
  - `4934`
  - `4935`
  - `4936`
  - `4937`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Detailed Directory Service Replication
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923E-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923E-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-directory-service-replication)

#### Directory Service Access

- Subcategory GUID: `{0CCE923B-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High on servers running AD DS role services.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4661`
  - `4662`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Access
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923B-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923B-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-access)

#### Directory Service Changes

- Subcategory GUID: `{0CCE923C-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High on Domain Controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `5136`
  - `5137`
  - `5138`
  - `5139`
  - `5141`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Changes
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes)

#### Directory Service Replication

- Subcategory GUID: `{0CCE923D-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium on Domain Controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - `4932`
  - `4933`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Replication
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923D-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923D-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-replication)

### Logon/Logoff

#### Account Lockout

- Subcategory GUID: `{0CCE9217-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4625

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Account Lockout
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-account-lockout)

#### User/Device Claims

- Subcategory GUID: `{0CCE9247-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `Low on a client computer.`
  - `Medium on a domain controller or network servers.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4626

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit User/Device Claims
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9247-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9247-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-device-claims)

#### Group Membership

- Subcategory GUID: `{0CCE9249-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `Low on a client computer.`
  - `Medium on a domain controller or network servers.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4627

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Group Membership
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-group-membership)

#### IPsec Extended Mode

- Subcategory GUID: `{0CCE921A-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4978
  - 4979
  - 4980
  - 4981
  - 4982
  - 4983
  - 4984

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Extended Mode
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921A-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921A-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-extended-mode)

#### IPsec Main Mode

- Subcategory GUID: `{0CCE9218-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4646
  - 4650
  - 4651
  - 4652
  - 4653
  - 4655
  - 4976
  - 5049
  - 5453

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Main Mode
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9218-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9218-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-main-mode)

#### IPsec Quick Mode

- Subcategory GUID: `{0CCE9219-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4977
  - 5451
  - 5452

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Quick Mode
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9219-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9219-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-quick-mode)

#### Logoff

- Subcategory GUID: `{0CCE9216-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4634
  - 4647

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Logoff
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logoff)

#### Logon

- Subcategory GUID: `{0CCE9215-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `Low on a client computer.`
  - `Medium on a domain controllers or network servers.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4624
  - 4625
  - 4648
  - 4675

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Logon
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon)

#### Network Policy Server

- Subcategory GUID: `{0CCE9243-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium to High on servers that are running Network Policy Server (NPS).`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 6272
  - 6273
  - 6274
  - 6275
  - 6276
  - 6277
  - 6278
  - 6279
  - 6280

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Network Policy Server
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-network-policy-server)

#### Other Logon/Logoff Events

- Subcategory GUID: `{0CCE921C-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4649
  - 4778
  - 4779
  - 4800
  - 4801
  - 4802
  - 4803
  - 5378
  - 5632
  - 5633

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Other Logon/Logoff Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-logonlogoff-events)

#### Special Logon

- Subcategory GUID: `{0CCE921B-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `Low on a client computer.`
  - `Medium on a domain controllers or network servers.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4964
  - 4672

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Special Logon
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-special-logon)

### Object Access

#### Application Generated

- Subcategory GUID: `{0CCE9222-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4665
  - 4666
  - 4667
  - 4668

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Application Generated
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-application-generated)

#### Certification Services

- Subcategory GUID: `{0CCE9221-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low to medium on servers that provide AD CS role services`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4868
  - 4869
  - 4870
  - 4871
  - 4872
  - 4873
  - 4874
  - 4875
  - 4876
  - 4877
  - 4878
  - 4879
  - 4880
  - 4881
  - 4882
  - 4883
  - 4884
  - 4885
  - 4886
  - 4887
  - 4888
  - 4889
  - 4890
  - 4891
  - 4892
  - 4893
  - 4894
  - 4895
  - 4896
  - 4897
  - 4898

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Certification Services
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-certification-services)

#### Detailed File Share

- Subcategory GUID: `{0CCE9244-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `High on file servers.`
  - `High on domain controllers because of SYSVOL network access required by Group Policy.`
  - `Low on member servers and workstations.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 5145

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Detailed File Share
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-file-share)

#### File Share

- Subcategory GUID: `{0CCE9224-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume:
  - `High on file servers.`
  - `High on domain controllers because of SYSVOL network access required by Group Policy.`
  - `Low on member servers and workstations.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 5140
  - 5142
  - 5143
  - 5144
  - 5168

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit File Share
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share)

#### File System

- Subcategory GUID: `{0CCE921D-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Varies, depending on how file system SACLs are configured`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4656
  - 4658
  - 4660
  - 4663
  - 4664
  - 4670
  - 4985
  - 5051

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit File System
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system)

#### Filtering Platform Connection

- Subcategory GUID: `{0CCE9226-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 5031
  - 5150
  - 5151
  - 5154
  - 5155
  - 5156
  - 5157
  - 5158
  - 5159

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Filtering Platform Connection
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)

#### Filtering Platform Packet Drop

- Subcategory GUID: `{0CCE9225-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 5152
  - 5153

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Filtering Platform Packet Drop
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-packet-drop)

#### Handle Manipulation

- Subcategory GUID: `{0CCE9223-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4658
  - 4690

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Handle Manipulation
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9223-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9223-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-handle-manipulation)

#### Kernel Object

- Subcategory GUID: `{0CCE921F-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4656
  - 4658
  - 4660
  - 4663

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Kernel Object
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921F-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921F-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kernel-object)

#### Other Object Access Events

- Subcategory GUID: `{0CCE9227-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium to High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4671
  - 4691
  - 4698
  - 4699
  - 4700
  - 4701
  - 4702
  - 5148
  - 5149
  - 5888
  - 5889
  - 5890

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Other Object Access Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events)

#### Registry

- Subcategory GUID: `{0CCE921E-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low to Medium, depending on how registry SACLs are configured.`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4656
  - 4657
  - 4658
  - 4660
  - 4663
  - 4670
  - 5039

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Registry
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-registry)

#### Removable Storage

- Subcategory GUID: `{0CCE9245-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4656
  - 4658
  - 4663

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Removable Storage
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-removable-storage)

#### SAM

- Subcategory GUID: `{0CCE9220-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High on domain controllers`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4661

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit SAM
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sam)

#### Central Access Policy Staging

- Subcategory GUID: `{0CCE9246-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4818

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Central Access Policy Staging
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9246-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9246-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-central-access-policy-staging)

### Policy Change

#### Audit Policy Change

- Subcategory GUID: `{0CCE922F-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4715
  - 4719
  - 4817
  - 4902
  - 4906
  - 4907
  - 4908
  - 4912
  - 4904
  - 4905

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Audit Policy Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change)

#### Authentication Policy Change

- Subcategory GUID: `{0CCE9230-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4670
  - 4706
  - 4707
  - 4716
  - 4713
  - 4717
  - 4718
  - 4739
  - 4864
  - 4865
  - 4866
  - 4867

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Authentication Policy Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-authentication-policy-change)

#### Authorization Policy Change

- Subcategory GUID: `{0CCE9231-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium to High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4703
  - 4704
  - 4705
  - 4670
  - 4911
  - 4913

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Authorization Policy Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-authorization-policy-change)

#### Filtering Platform Policy Change

- Subcategory GUID: `{0CCE9233-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4709
  - 4710
  - 4711
  - 4712
  - 5040
  - 5041
  - 5042
  - 5043
  - 5044
  - 5045
  - 5046
  - 5047
  - 5048
  - 5440
  - 5441
  - 5442
  - 5443
  - 5444
  - 5446
  - 5448
  - 5449
  - 5450
  - 5456
  - 5457
  - 5458
  - 5459
  - 5460
  - 5461
  - 5462
  - 5463
  - 5464
  - 5465
  - 5466
  - 5467
  - 5468
  - 5471
  - 5472
  - 5473
  - 5474
  - 5477

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Filtering Platform Policy Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-policy-change)

#### MPSSVC Rule-Level Policy Change

- Subcategory GUID: `{0CCE9232-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4944
  - 4945
  - 4946
  - 4947
  - 4948
  - 4949
  - 4950
  - 4951
  - 4952
  - 4953
  - 4954
  - 4956
  - 4957
  - 4958

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit MPSSVC Rule-Level Policy Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9232-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9232-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-mpssvc-rule-level-policy-change)

#### Other Policy Change Events

- Subcategory GUID: `{0CCE9234-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium to High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4714
  - 4819
  - 4826
  - 4909
  - 4910
  - 5063
  - 5064
  - 5065
  - 5066
  - 5067
  - 5068
  - 5069
  - 5070
  - 5447
  - 6144
  - 6145

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Other Policy Change Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9234-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9234-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-policy-change-events)

### Privilege Use

#### Non Sensitive Privilege Use

- Subcategory GUID: `{0CCE9229-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Very High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4673
  - 4674
  - 4985

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Privilege Use
                        - Audit Non Sensitive Privilege Use
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9229-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9229-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-non-sensitive-privilege-use)

#### Other Privilege Use Events

- Subcategory GUID: `{0CCE922A-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: TBD
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4985

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Privilege Use
                          - Audit Other Privilege Use Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE922A-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE922A-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-privilege-use-events)

#### Sensitive Privilege Use

- Subcategory GUID: `{0CCE9228-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4673, 4674, 4985

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Privilege Use
                          - Audit Sensitive Privilege Use
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sensitive-privilege-use)

### System

#### IPsec Driver

- Subcategory GUID: `{0CCE9213-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Medium`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4960
  - 4961
  - 4962
  - 4963
  - 4965
  - 5478
  - 5479
  - 5480
  - 5483
  - 5484
  - 5485

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit IPsec Driver
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9213-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9213-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-driver)

#### Other System Events

- Subcategory GUID: `{0CCE9214-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 5024
  - 5025
  - 5027
  - 5028
  - 5029
  - 5030
  - 5032
  - 5033
  - 5034
  - 5035
  - 5037
  - 5058
  - 5059
  - 6400
  - 6401
  - 6402
  - 6403
  - 6404
  - 6405
  - 6406
  - 6407
  - 6408
  - 6409

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Other System Events
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-system-events)

#### Security State Change

- Subcategory GUID: `{0CCE9210-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4608
  - 4616
  - 4621

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Security State Change
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-state-change)

#### Security System Extension

- Subcategory GUID: `{0CCE9211-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4610
  - 4611
  - 4614
  - 4622
  - 4697

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Security System Extension
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-system-extension)

#### System Integrity

- Subcategory GUID: `{0CCE9212-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `Low`
- API Mapping: [Learn More](https://github.com/jsecurity101/TelemetrySource/tree/main/Microsoft-Windows-Security-Auditing)
- EventID(s):
  - 4612
  - 4615
  - 4618
  - 4816
  - 5038
  - 5056
  - 5062
  - 5057
  - 5060
  - 5061
  - 6281
  - 6410

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit System Integrity
                            - Success and Failure
```

Alternatively you can enable logging via `auditpol` using the following command(s):

```powershell
# Enable Success audit Only
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030}, /success:enable

# Enable both Success and Failure auditing
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030}, /success:enable /failure:enable
```

If you want to learn more about this sub-category. You can do so via MSDN - [Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-system-integrity)

### Global Object Access Auditing

TBD

## Full Event(s) List

<details>
    <summary>Expand Full List</summary>

- [1100: The event logging service has shut down.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1100)
- [1102: The audit log was cleared.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
- [1104: The security log is now full.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1104)
- [1105: Event log automatic backup.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1105)
- [1108: The event logging service encountered an error while processing an incoming event published from %1](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1108)
- [4608: Windows is starting up.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4608)
- [4610: An authentication package has been loaded by the Local Security Authority.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4610)
- [4611: A trusted logon process has been registered with the Local Security Authority.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4611)
- [4612: Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4612)
- [4614: A notification package has been loaded by the Security Account Manager.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4614)
- [4615: Invalid use of LPC port.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4615)
- [4616: The system time was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616)
- [4618: A monitored security event pattern has occurred.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4618)
- [4621: Administrator recovered system from CrashOnAuditFail.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4621)
- [4622: A security package has been loaded by the Local Security Authority.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4622)
- [4624: An account was successfully logged on.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [4625: An account failed to log on.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [4625: An account failed to log on.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [4626: User/Device claims information.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4626)
- [4627: Group membership information.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4627)
- [4634: An account was logged off.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634)
- [4646: Security ID: %1](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4646)
- [4647: User initiated logoff.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647)
- [4648: A logon was attempted using explicit credentials.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648)
- [4649: A replay attack was detected.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4649)
- [4650: An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4650)
- [4651: An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4651)
- [4652: An IPsec Main Mode negotiation failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4652)
- [4653: An IPsec Main Mode negotiation failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4653)
- [4655: An IPsec Main Mode security association ended.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4655)
- [4656: A handle to an object was requested.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4656)
- [4657: A registry value was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657)
- [4658: The handle to an object was closed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4658)
- [4660: An object was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4660)
- [4661: A handle to an object was requested.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4661)
- [4662: An operation was performed on an object.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [4663: An attempt was made to access an object.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [4664: An attempt was made to create a hard link.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4664)
- [4665: An attempt was made to create an application client context.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4665)
- [4666: An application attempted an operation.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4666)
- [4667: An application client context was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4667)
- [4668: An application was initialized.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4668)
- [4670: Permissions on an object were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670)
- [4671: An application attempted to access a blocked ordinal through the TBS.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4671)
- [4672: Special privileges assigned to new logon.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [4673: A privileged service was called.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673)
- [4674: An operation was attempted on a privileged object.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4674)
- [4675: SIDs were filtered.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4675)
- [4688: A new process has been created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [4689: A process has exited.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4689)
- [4690: An attempt was made to duplicate a handle to an object.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4690)
- [4691: Indirect access to an object was requested.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4691)
- [4692: Backup of data protection master key was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4692)
- [4693: Recovery of data protection master key was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4693)
- [4694: Protection of auditable protected data was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4694)
- [4695: Unprotection of auditable protected data was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4695)
- [4696: A primary token was assigned to process.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4696)
- [4697: A service was installed in the system.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)
- [4698: A scheduled task was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)
- [4699: A scheduled task was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4699)
- [4700: A scheduled task was enabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4700)
- [4701: A scheduled task was disabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4701)
- [4702: A scheduled task was updated.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702)
- [4703: A user right was adjusted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4703)
- [4703: A user right was adjusted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4703)
- [4704: A user right was assigned.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4704)
- [4705: A user right was removed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4705)
- [4706: A new trust was created to a domain.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4706)
- [4707: A trust to a domain was removed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4707)
- [4709: IPsec Services was started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4709)
- [4710: IPsec Services was disabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4710)
- [4711: May contain any one of the following:](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4711)
- [4712: IPsec Services encountered a potentially serious failure.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4712)
- [4713: Kerberos policy was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4713)
- [4714: Encrypted data recovery policy was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4714)
- [4715: The audit policy (SACL) on an object was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4715)
- [4716: Trusted domain information was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4716)
- [4717: System security access was granted to an account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4717)
- [4718: System security access was removed from an account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4718)
- [4719: System audit policy was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719)
- [4720: A user account was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [4722: A user account was enabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4722)
- [4723: An attempt was made to change an account's password.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4723)
- [4724: An attempt was made to reset an account's password.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724)
- [4725: A user account was disabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4725)
- [4726: A user account was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4726)
- [4727: A security-enabled global group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4727)
- 4728: A member was added to a security-enabled global group
- [4729: A member was removed from a security-enabled global group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4729)
- [4730: A security-enabled global group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4730)
- [4731: A security-enabled local group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4731)
- [4732: A member was added to a security-enabled local group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732)
- [4733: A member was removed from a security-enabled local group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4733)
- [4734: A security-enabled local group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4734)
- [4735: A security-enabled local group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4735)
- [4737: A security-enabled global group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4737)
- [4738: A user account was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738)
- [4739: Domain Policy was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4739)
- [4740: A user account was locked out.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740)
- [4741: A computer account was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741)
- [4742: A computer account was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4742)
- [4743: A computer account was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4743)
- [4744: A security-disabled local group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4744)
- [4745: A security-disabled local group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4745)
- [4746: A member was added to a security-disabled local group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4746)
- [4747: A member was removed from a security-disabled local group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4747)
- [4748: A security-disabled local group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4748)
- [4749: A security-disabled global group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4749)
- [4750: A security-disabled global group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4750)
- [4751: A member was added to a security-disabled global group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4751)
- [4752: A member was removed from a security-disabled global group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4752)
- [4753: A security-disabled global group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4753)
- [4754: A security-enabled universal group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4754)
- [4755: A security-enabled universal group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4755)
- [4756: A member was added to a security-enabled universal group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4756)
- [4757: A member was removed from a security-enabled universal group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4757)
- [4758: A security-enabled universal group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4758)
- [4759: A security-disabled universal group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4759)
- [4760: A security-disabled universal group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4760)
- [4761: A member was added to a security-disabled universal group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4761)
- [4762: A member was removed from a security-disabled universal group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4762)
- [4763: A security-disabled universal group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4763)
- [4764: A group's type was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4764)
- [4765: SID History was added to an account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4765)
- [4766: An attempt to add SID History to an account failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4766)
- [4767: A user account was unlocked.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4767)
- [4768: A Kerberos authentication ticket (TGT) was requested.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [4769: A Kerberos service ticket was requested.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [4770: A Kerberos service ticket was renewed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4770)
- [4771: Kerberos pre-authentication failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771)
- [4772: A Kerberos authentication ticket request failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4772)
- [4773: A Kerberos service ticket request failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4773)
- [4774: An account was mapped for logon.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4774)
- [4775: An account could not be mapped for logon.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4775)
- [4776: The computer attempted to validate the credentials for an account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)
- [4777: The domain controller failed to validate the credentials for an account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4777)
- [4778: A session was reconnected to a Window Station.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778)
- [4779: A session was disconnected from a Window Station.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4779)
- [4780: The ACL was set on accounts which are members of administrators groups.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4780)
- [4781: The name of an account was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4781)
- [4782: The password hash of an account was accessed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4782)
- [4783: A basic application group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4783)
- [4784: A basic application group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4784)
- [4785: A member was added to a basic application group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4785)
- [4786: A member was removed from a basic application group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4786)
- [4787: A non-member was added to a basic application group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4787)
- [4788: A non-member was removed from a basic application group.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4788)
- [4789: A basic application group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4789)
- [4790: An LDAP query group was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4790)
- [4791: An LDAP query group was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4791)
- [4792: An LDAP query group was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4792)
- [4793: The Password Policy Checking API was called.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4793)
- [4794: An attempt was made to set the Directory Services Restore Mode administrator password.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4794)
- [4798: A user's local group membership was enumerated.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798)
- [4799: A security-enabled local group membership was enumerated.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4799)
- [4800: The workstation was locked.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4800)
- [4801: The workstation was unlocked.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4801)
- [4802: The screen saver was invoked.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4802)
- [4803: The screen saver was dismissed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4803)
- [4816: RPC detected an integrity violation while decrypting an incoming message.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4816)
- [4817: Auditing settings on object were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4817)
- [4818: Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4818)
- [4819: Central Access Policies on the machine have been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4819)
- [4826: Boot Configuration Data loaded.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4826)
- [4864: A namespace collision was detected.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4864)
- [4865: A trusted forest information entry was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4865)
- [4866: A trusted forest information entry was removed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4866)
- [4867: A trusted forest information entry was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4867)
- [4868: The certificate manager denied a pending certificate request.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4868)
- [4869: Certificate Services received a resubmitted certificate request.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4869)
- [4870: Certificate Services revoked a certificate.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4870)
- [4871: Certificate Services received a request to publish the certificate revocation list (CRL).](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4871)
- [4872: Certificate Services published the certificate revocation list (CRL).](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4872)
- [4873: A certificate request extension changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4873)
- [4874: One or more certificate request attributes changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4874)
- [4875: Certificate Services received a request to shut down.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4875)
- [4876: Certificate Services backup started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4876)
- [4877: Certificate Services backup completed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4877)
- [4878: Certificate Services restore started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4878)
- [4879: Certificate Services restore completed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4879)
- [4880: Certificate Services started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4880)
- [4881: Certificate Services stopped.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4881)
- [4882: The security permissions for Certificate Services changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4882)
- [4883: Certificate Services retrieved an archived key.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4883)
- [4884: Certificate Services imported a certificate into its database.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4884)
- [4885: The audit filter for Certificate Services changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4885)
- [4886: Certificate Services received a certificate request.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4886)
- [4887: Certificate Services approved a certificate request and issued a certificate.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4887)
- [4888: Certificate Services denied a certificate request.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4888)
- [4889: Certificate Services set the status of a certificate request to pending.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4889)
- [4890: The certificate manager settings for Certificate Services changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4890)
- [4891: A configuration entry changed in Certificate Services.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4891)
- [4892: A property of Certificate Services changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4892)
- [4893: Certificate Services archived a key.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4893)
- [4894: Certificate Services imported and archived a key.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4894)
- [4895: Certificate Services published the CA certificate to Active Directory Domain Services.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4895)
- [4896: One or more rows have been deleted from the certificate database.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4896)
- [4897: Role separation enabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4897)
- [4898: Certificate Services loaded a template.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4898)
- [4902: The Per-user audit policy table was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4902)
- [4904: An attempt was made to register a security event source.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4904)
- [4905: An attempt was made to unregister a security event source.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4905)
- [4906: The CrashOnAuditFail value has changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4906)
- [4907: Auditing settings on object were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4907)
- [4908: Special Groups Logon table modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4908)
- [4909: The local policy settings for the TBS were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4909)
- [4910: The group policy settings for the TBS were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4910)
- [4911: Resource attributes of the object were changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4911)
- [4912: Per User Audit Policy was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4912)
- [4913: Central Access Policy on the object was changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4913)
- [4928: An Active Directory replica source naming context was established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4928)
- [4929: An Active Directory replica source naming context was removed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4929)
- [4930: An Active Directory replica source naming context was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4930)
- [4931: An Active Directory replica destination naming context was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4931)
- [4932: Synchronization of a replica of an Active Directory naming context has begun.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4932)
- [4933: Synchronization of a replica of an Active Directory naming context has ended.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4933)
- [4934: Attributes of an Active Directory object were replicated.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4934)
- [4935: Replication failure begins.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4935)
- [4936: Replication failure ends.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4936)
- [4937: A lingering object was removed from a replica.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4937)
- [4944: The following policy was active when the Windows Firewall started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4944)
- [4945: A rule was listed when the Windows Firewall started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4945)
- [4946: A change has been made to Windows Firewall exception list. A rule was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4946)
- [4947: A change has been made to Windows Firewall exception list. A rule was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4947)
- [4948: A change has been made to Windows Firewall exception list. A rule was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4948)
- [4949: Windows Firewall settings were restored to the default values.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4949)
- [4950: A Windows Firewall setting has changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4950)
- [4951: A rule has been ignored because its major version number was not recognized by Windows Firewall.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4951)
- [4952: Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4952)
- [4953: A rule has been ignored by Windows Firewall because it could not parse the rule.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4953)
- [4954: Windows Firewall Group Policy settings have changed. The new settings have been applied.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4954)
- [4956: Windows Firewall has changed the active profile.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4956)
- [4957: Windows Firewall did not apply the following rule:](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4957)
- [4958: Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer:](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4958)
- [4960: IPsec dropped an inbound packet that failed an integrity check.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4960)
- 4961: IPsec dropped an inbound packet that failed a replay check.
- 4962: IPsec dropped an inbound packet that failed a replay check.
- [4963: IPsec dropped an inbound clear text packet that should have been secured.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4963)
- [4964: Special groups have been assigned to a new logon.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4964)
- [4965: IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4965)
- [4976: During Main Mode negotiation, IPsec received an invalid negotiation packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4976)
- [4977: During Quick Mode negotiation, IPsec received an invalid negotiation packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4977)
- [4978: During Extended Mode negotiation, IPsec received an invalid negotiation packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4978)
- [4979: IPsec Main Mode and Extended Mode security associations were established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4979)
- [4980: IPsec Main Mode and Extended Mode security associations were established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4980)
- [4981: IPsec Main Mode and Extended Mode security associations were established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4981)
- [4982: IPsec Main Mode and Extended Mode security associations were established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4982)
- [4983: An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4983)
- [4984: An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4984)
- [4985: The state of a transaction has changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4985)
- [5024: The Windows Firewall Service has started successfully.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5024)
- [5025: The Windows Firewall Service has been stopped.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5025)
- [5027: The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5027)
- [5028: The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5028)
- [5029: The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5029)
- [5030: The Windows Firewall Service failed to start.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5030)
- [5031: The Windows Firewall Service blocked an application from accepting incoming connections on the network.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5031)
- [5032: Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5032)
- [5033: The Windows Firewall Driver has started successfully.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5033)
- [5034: The Windows Firewall Driver was stopped.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5034)
- [5035: The Windows Firewall Driver failed to start.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5035)
- [5037: The Windows Firewall Driver detected critical runtime error. Terminating.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5037)
- [5038: Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5038)
- [5039: A registry key was virtualized.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5039)
- [5040: A change has been made to IPsec settings. An Authentication Set was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5040)
- [5041: A change has been made to IPsec settings. An Authentication Set was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5041)
- [5042: A change has been made to IPsec settings. An Authentication Set was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5042)
- [5043: A change has been made to IPsec settings. A Connection Security Rule was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5043)
- [5044: A change has been made to IPsec settings. A Connection Security Rule was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5044)
- [5045: A change has been made to IPsec settings. A Connection Security Rule was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5045)
- [5046: A change has been made to IPsec settings. A Crypto Set was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5046)
- [5047: A change has been made to IPsec settings. A Crypto Set was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5047)
- [5048: A change has been made to IPsec settings. A Crypto Set was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5048)
- [5049: An IPsec Security Association was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5049)
- [5051: A file was virtualized.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5051)
- [5056: A cryptographic self-test was performed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5056)
- [5057: A cryptographic primitive operation failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5057)
- [5058: Key file operation.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5058)
- [5059: Key migration operation.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5059)
- [5060: Verification operation failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5060)
- [5061: Cryptographic operation.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5061)
- [5062: A kernel-mode cryptographic self-test was performed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5062)
- [5063: A cryptographic provider operation was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5063)
- [5064: A cryptographic context operation was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5064)
- [5065: A cryptographic context modification was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5065)
- [5066: A cryptographic function operation was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5066)
- [5067: A cryptographic function modification was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5067)
- [5068: A cryptographic function provider operation was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5068)
- [5069: A cryptographic function property operation was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5069)
- [5070: A cryptographic function property modification was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5070)
- [5136: A directory service object was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136)
- [5137: A directory service object was created.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5137)
- [5138: A directory service object was undeleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5138)
- [5139: A directory service object was moved.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5139)
- [5140: A network share object was accessed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140)
- [5141: A directory service object was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5141)
- [5142: A network share object was added.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5142)
- [5143: A network share object was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5143)
- [5144: A network share object was deleted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5144)
- [5145: A network share object was checked to see whether client can be granted desired access.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)
- [5148: The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5148)
- [5149: The DoS attack has subsided and normal processing is being resumed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5149)
- [5150: The Windows Filtering Platform blocked a packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5150)
- [5151: A more restrictive Windows Filtering Platform filter has blocked a packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5151)
- [5152: The Windows Filtering Platform blocked a packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5152)
- [5153: A more restrictive Windows Filtering Platform filter has blocked a packet.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5153)
- [5154: The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5154)
- [5155: The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5155)
- [5156: The Windows Filtering Platform has permitted a connection.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)
- [5157: The Windows Filtering Platform has blocked a connection.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157)
- [5158: The Windows Filtering Platform has permitted a bind to a local port.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5158)
- [5159: The Windows Filtering Platform has blocked a bind to a local port.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5159)
- [5168: SPN check for SMB/SMB2 failed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5168)
- [5376: Credential Manager credentials were backed up.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5376)
- [5377: Credential Manager credentials were restored from a backup.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5377)
- [5378: The requested credentials delegation was disallowed by policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5378)
- [5440: The following callout was present when the Windows Filtering Platform Base Filtering Engine started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5440)
- [5441: The following filter was present when the Windows Filtering Platform Base Filtering Engine started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5441)
- [5442: The following provider was present when the Windows Filtering Platform Base Filtering Engine started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5442)
- [5443: The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5443)
- [5444: The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5444)
- [5446: A Windows Filtering Platform callout has been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5446)
- [5447: A Windows Filtering Platform filter has been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5447)
- [5448: A Windows Filtering Platform provider has been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5448)
- [5449: A Windows Filtering Platform provider context has been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5449)
- [5450: A Windows Filtering Platform sub-layer has been changed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5450)
- [5451: An IPsec Quick Mode security association was established.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5451)
- [5452: An IPsec Quick Mode security association ended.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5452)
- [5453: An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5453)
- [5456: PAStore Engine applied Active Directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5456)
- [5457: PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5457)
- [5458: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5458)
- [5459: PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5459)
- [5460: PAStore Engine applied local registry storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5460)
- [5461: PAStore Engine failed to apply local registry storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5461)
- [5462: PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5462)
- [5463: PAStore Engine polled for changes to the active IPsec policy and detected no changes.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5463)
- [5464: PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5464)
- [5465: PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5465)
- [5466: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5466)
- [5467: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy. The cached copy of the Active Directory IPsec policy is no longer being used.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5467)
- [5468: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5468)
- [5471: PAStore Engine loaded local storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5471)
- [5472: PAStore Engine failed to load local storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5472)
- [5473: PAStore Engine loaded directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5473)
- [5474: PAStore Engine failed to load directory storage IPsec policy on the computer.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5474)
- [5477: PAStore Engine failed to add quick mode filter.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5477)
- [5478: IPsec Services has started successfully.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5478)
- 5479: IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5480: IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be started.
- 5484: IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5485: IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- [5632: A request was made to authenticate to a wireless network.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5632)
- [5633: A request was made to authenticate to a wired network.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5633)
- [5712: A Remote Procedure Call (RPC) was attempted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5712)
- [5888: An object in the COM+ Catalog was modified.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5888)
- [5889: An object was deleted from the COM+ Catalog.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5889)
- [5890: An object was added to the COM+ Catalog.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5890)
- [6144: Security policy in the group policy objects has been applied successfully.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6144)
- [6145: One or more errors occurred while processing security policy in the group policy objects.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6145)
- [6272: Network Policy Server granted access to a user.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6272)
- [6273: Network Policy Server denied access to a user.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6273)
- [6274: Network Policy Server discarded the request for a user.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6274)
- [6275: Network Policy Server discarded the accounting request for a user.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6275)
- [6276: Network Policy Server quarantined a user.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6276)
- [6277: Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6277)
- [6278: Network Policy Server granted full access to a user because the host met the defined health policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6278)
- [6279: Network Policy Server locked the user account due to repeated failed authentication attempts.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6279)
- [6280: Network Policy Server unlocked the user account.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6280)
- [6281: Code Integrity determined that the page hashes of an image file are not valid. The file could be improperly signed without page hashes or corrupt due to unauthorized modification. The invalid hashes could indicate a potential disk device error.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6281)
- [6400: BranchCache: Received an incorrectly formatted response while discovering availability of content.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6400)
- [6401: BranchCache: Received invalid data from a peer. Data discarded.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6401)
- [6402: BranchCache: The message to the hosted cache offering it data is incorrectly formatted.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6402)
- [6403: BranchCache: The hosted cache sent an incorrectly formatted response to the client.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6403)
- [6404: BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6404)
- [6405: BranchCache: %2 instance(s) of event id %1 occurred.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6405)
- [6406: %1 registered to Windows Firewall to control filtering for the following: %2](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6406)
- 6407: N/A
- [6408: Registered product %1 failed and Windows Firewall is now controlling the filtering for %2](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6408)
- [6409: BranchCache: A service connection point object could not be parsed.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6409)
- [6410: Code integrity determined that a file does not meet the security requirements to load into a process.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6410)
- [6416: A new external device was recognized by the System](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6416)
- [6419: A request was made to disable a device](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6419)
- [6420: A device was disabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6420)
- [6421: A request was made to enable a device.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6421)
- [6422: A device was enabled.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6422)
- [6423: The installation of this device is forbidden by system policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6423)
- [6424: The installation of this device was allowed, after having previously been forbidden by policy.](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6424)

</details>

## Event Fields

### Provider: Microsoft Windows Security Auditing / EventID: 4624

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- TargetUserSid
- TargetUserName
- TargetDomainName
- TargetLogonId
- LogonType
- LogonProcessName
- AuthenticationPackageName
- WorkstationName
- LogonGuid
- TransmittedServices
- LmPackageName
- KeyLength
- ProcessId
- ProcessName
- IpAddress
- IpPort
- ImpersonationLevel
- RestrictedAdminMode
- RemoteCredentialGuard
- TargetOutboundUserName
- TargetOutboundDomainName
- VirtualAccount
- TargetLinkedLogonId
- ElevatedToken
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4627

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- TargetUserSid
- TargetUserName
- TargetDomainName
- TargetLogonId
- LogonType
- EventIdx
- EventCountTotal
- GroupMembership
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4663

<details>
    <summary>Expand Details</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- ObjectServer
- ObjectType
- ObjectName
- HandleId
- AccessList
- AccessMask
- ProcessId
- ProcessName
- ResourceAttributes
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4670

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- ObjectServer
- ObjectType
- ObjectName
- HandleId
- OldSd
- NewSd
- ProcessId
- ProcessName
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4672

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- PrivilegeList
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4673

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- ObjectServer
- Service
- PrivilegeList
- ProcessId
- ProcessName
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4688

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- NewProcessId
- NewProcessName
- TokenElevationType
- ProcessId
- CommandLine
- TargetUserSid
- TargetUserName
- TargetDomainName
- TargetLogonId
- ParentProcessName
- MandatoryLabel
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4689

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- Status
- ProcessId
- ProcessName
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4702

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- TaskName
- TaskContentNew
- ClientProcessStartKey
- ClientProcessId
- ParentProcessId
- RpcCallClientLocality
- FQDN
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4703

<details>
    <summary>Expand</summary>

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- TargetUserSid
- TargetUserName
- TargetDomainName
- TargetLogonId
- ProcessName
- ProcessId
- EnabledPrivilegeList
- DisabledPrivilegeList
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 4957

<details>
    <summary>Expand</summary>

```yml
- RuleId
- RuleName
- RuleAttr
```

</details>

### Provider: Microsoft Windows Security Auditing / EventID: 5447

<details>
    <summary>Expand</summary>

```yml
- ProcessId
- UserSid
- UserName
- ProviderKey
- ProviderName
- ChangeType
- FilterKey
- FilterName
- FilterType
- FilterId
- LayerKey
- LayerName
- LayerId
- Weight
- Conditions
- Action
- CalloutKey
- CalloutName
```

</details>
