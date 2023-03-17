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
    - [Provider: Microsoft Windows Security Auditing / EventID: 4688](#provider-microsoft-windows-security-auditing--eventid-4688)
      - [Process Creation Logging](#process-creation-logging)
      - [Command-Line Logging](#command-line-logging)
    - [Provider: Microsoft-Windows-Sysmon / EventID: 1](#provider-microsoft-windows-sysmon--eventid-1)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4688](#provider-microsoft-windows-security-auditing--eventid-4688-1)
    - [Provider: Microsoft-Windows-Sysmon / EventID: 1](#provider-microsoft-windows-sysmon--eventid-1-1)

</details>

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `process_creation` category

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

This section described how to setup logging in your environment

### Provider: Microsoft Windows Security Auditing / EventID: 4688

You can enable the following settings locally by using `gpedit.msc` or via `GPO` if you're in a domain environment

#### Process Creation Logging

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Process Creation
```

#### Command-Line Logging

```yml
- Computer Configuration
    - Administrative Templates
        - System
            - Audit Process Creation
                - Include Command Line In Process Creation Events
```

### Provider: Microsoft-Windows-Sysmon / EventID: 1

- Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Install Sysmon using an appropriate configuration. The configuration must include a `<ProcessCreate>` element. We recommend the following configuration [sysmonconfig-export.xml](https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-export.xml).

```cmd
sysmon -i /path/to/config
```

## Event Fields

Note: For rules using this category in SIGMA. Know that there is a mapping between `Sysmon EID 1` fields and `Microsoft Windows Security Auditing EID: 4688`. While you can use the fields of `EID 4688` it's best to use the Sysmon ones.

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
