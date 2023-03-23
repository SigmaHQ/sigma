# category: ps_module

ID: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b

## Content

<details>
    <summary>Expand</summary>

- [category: ps\_module](#category-ps_module)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
    - [PowerShell 5](#powershell-5)
    - [PowerShell 7](#powershell-7)
  - [Logging Setup](#logging-setup)
    - [Microsoft-Windows-PowerShell](#microsoft-windows-powershell)
    - [Provider: PowerShellCore](#provider-powershellcore)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)](#provider-microsoft-windows-powershell--eventid-4103-powershell-5)
    - [Provider: PowerShellCore / EventID: 4103 (PowerShell 7)](#provider-powershellcore--eventid-4103-powershell-7)

</details>

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `ps_module` category.

## Event Source(s)

### PowerShell 5

```yml
Provider: Microsoft-Windows-PowerShell
GUID: {a0c1853b-5c40-4b15-8766-3cf1c58f985a}
Channel: Microsoft-Windows-PowerShell/Operational
EventID: 4103
```

### PowerShell 7

```yml
Provider: PowerShellCore
GUID: {f90714a8-5509-434a-bf6d-b1624c8a19a2}
Channel: PowerShellCore/Operational
EventID: 4103
```

## Logging Setup

### Microsoft-Windows-PowerShell

- Event Volume: TBD
- EventID(s):
  - `4103`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On Module Logging
                  - Select List Of Modules According To Your Audit Policy (or use '*' to select all modules)
```

### Provider: PowerShellCore

- Event Volume: TBD
- EventID(s):
  - `4103`

If you're using `gpedit.msc` or similar you can enable logging for this category by following the structure below

```yml
- Computer Configuration
    - Administrative Templates
        - PowerShell Core
            - Turn On Module Logging
              - Select List Of Modules According To Your Audit Policy (or use '*' to select all modules)
```

> **Note**
>
> By default when you install PowerShell 7 the logging template isn't available. You can install it by using the PowerShell script available in the installation directory `InstallPSCorePolicyDefinitions.ps1`

## Event Fields

### Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)

<details>
    <summary>Expand</summary>

```yml
- ContextInfo
- UserData
- Payload
```

</details>

### Provider: PowerShellCore / EventID: 4103 (PowerShell 7)

<details>
    <summary>Expand</summary>

```yml
- ContextInfo
- UserData
- Payload
```

</details>
