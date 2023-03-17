# category: ps_script

ID: bade5735-5ab0-4aa7-a642-a11be0e40872

## Content

<details>
    <summary>Expand</summary>

- [category: ps\_script](#category-ps_script)
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

</details>

## Description

This logsource guide describes how to enable the necessary logging to make use of SIGMA rules that leverage the `ps_script` category

## Event Source(s)

### PowerShell 5

```yml
Provider: Microsoft-Windows-PowerShell
GUID: {a0c1853b-5c40-4b15-8766-3cf1c58f985a}
Channel: Microsoft-Windows-PowerShell/Operational
EventID: 4104
```

### PowerShell 7

```yml
Provider: PowerShellCore
GUID: {f90714a8-5509-434a-bf6d-b1624c8a19a2}
Channel: PowerShellCore/Operational
EventID: 4104
```

## Logging Setup

You can enable the following settings locally by using `gpedit.msc` or via `GPO` if you're in a domain environment

### Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)

```yml
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On PowerShell Script Block Logging
```

### Provider: PowerShellCore / EventID: 4103 (PowerShell 7)

```yml
- Computer Configuration
    - Administrative Templates
        - PowerShell Core
            - Turn On PowerShell Script Block Logging
```

## Event Fields

### Provider: Microsoft-Windows-PowerShell / EventID: 4103 (PowerShell 5)

<details>
    <summary>Expand</summary>

```yml
- MessageNumber
- MessageTotal
- ScriptBlockText
- ScriptBlockId
- Path
```

</details>

### Provider: PowerShellCore / EventID: 4103 (PowerShell 7)

<details>
    <summary>Expand</summary>

```yml
- MessageNumber
- MessageTotal
- ScriptBlockText
- ScriptBlockId
- Path
```
</details>
