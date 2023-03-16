# category: ps_module

ID: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b

## Content

- [category: ps\_module](#category-ps_module)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
    - [PowerShell 5](#powershell-5)
    - [PowerShell 7](#powershell-7)
  - [Logging Setup](#logging-setup)
    - [Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)](#provider-microsoft-windows-powershell--eventid-4103-powershell-5)
    - [Provider: PowerShellCore / EventID: 4103 (PowerShell 7)](#provider-powershellcore--eventid-4103-powershell-7)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)](#provider-microsoft-windows-powershell--eventid-4103-powershell-5-1)
    - [Provider: PowerShellCore / EventID: 4103 (PowerShell 7)](#provider-powershellcore--eventid-4103-powershell-7-1)

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `ps_module` category

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

You can enable the following settings locally by using `gpedit.msc` or via `GPO` if you're in a domain environment

### Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)

```yml
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On Module Logging
```

### Provider: PowerShellCore / EventID: 4103 (PowerShell 7)

```yml
- Computer Configuration
    - Administrative Templates
        - PowerShell Core
            - Turn On Module Logging
```

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
