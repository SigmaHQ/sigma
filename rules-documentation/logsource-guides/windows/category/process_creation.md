# category: process_creation

ID: 2ff912e8-159f-4789-a2ef-761292b32a23

## Content

<details>
    <summary>Expand</summary>

- [category: process\_creation](#category-process_creation)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Microsoft Windows Security Auditing](#microsoft-windows-security-auditing)
      - [Process Creation](#process-creation)
      - [Include Command-Line In Process Creation Events](#include-command-line-in-process-creation-events)
    - [Microsoft-Windows-Sysmon](#microsoft-windows-sysmon)
      - [Process Creation](#process-creation-1)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4688](#provider-microsoft-windows-security-auditing--eventid-4688)
    - [Provider: Microsoft-Windows-Sysmon / EventID: 1](#provider-microsoft-windows-sysmon--eventid-1)

</details>

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `process_creation` category.

## Event Source(s)

This section describes the event source(s) that are required to be collected in order to receive the events used by the `process_creation` category detection rules

```yml
Provider: Microsoft Windows Security Auditing
GUID: {54849625-5478-4994-a5ba-3e3b0328c30d}
Channel: Security
EventID: 4688
```

```yml
Provider: Microsoft-Windows-Sysmon
GUID: {5770385f-c22a-43e0-bf4c-06f5698ffbd9}
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 1
```

## Logging Setup

This section describes how to setup logging in your environment

### Microsoft Windows Security Auditing

#### Process Creation

- Subcategory GUID: `{0CCE922B-69AE-11D9-BED3-505054503030}`
- Provider: `Microsoft Windows Security Auditing`
- Channel: `Security`
- Event Volume: `High`
- EventID(s):
  - `4688`

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

#### Include Command-Line In Process Creation Events

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Administrative Templates
        - System
            - Audit Process Creation
                - Include Command Line In Process Creation Events
```

### Microsoft-Windows-Sysmon

#### Process Creation

- Provider: `Microsoft-Windows-Sysmon`
- Channel: `Microsoft-Windows-Sysmon/Operational`
- Event Volume: `High`
- EventID(s):
  - `1`

To configure Sysmon process creation events you can follow the instructions below

- Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Install Sysmon using an appropriate configuration. The configuration must include a `<ProcessCreate>` element. We recommend the following configuration [sysmonconfig-export.xml](https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-export.xml).

```powershell
sysmon -i /path/to/config
```

## Event Fields

> **Note**
>
> For rules using this category in SIGMA. Know that there is a mapping between `Sysmon EID 1` fields and `Microsoft Windows Security Auditing EID: 4688`. While you can use the fields of `EID 4688` it's best to use the Sysmon ones.

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

### Provider: Microsoft-Windows-Sysmon / EventID: 1

<details>
    <summary>Expand</summary>

```yml
- RuleName
- UtcTime
- ProcessGuid
- ProcessId
- Image
- FileVersion
- Description
- Product
- Company
- OriginalFileName
- CommandLine
- CurrentDirectory
- User
- LogonGuid
- LogonId
- TerminalSessionId
- IntegrityLevel
- Hashes
- ParentProcessGuid
- ParentProcessId
- ParentImage
- ParentCommandLine
- ParentUser
```

</details>
