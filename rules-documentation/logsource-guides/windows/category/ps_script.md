# category: ps_script

ID: bade5735-5ab0-4aa7-a642-a11be0e40872

## Content

- [category: ps\_script](#category-ps_script)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Provider: Microsoft-Windows-PowerShell / EventID: 4103](#provider-microsoft-windows-powershell--eventid-4103)
    - [Provider: PowerShellCore / EventID: 4103](#provider-powershellcore--eventid-4103)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft-Windows-PowerShell / EventID: 4103](#provider-microsoft-windows-powershell--eventid-4103-1)
    - [Provider: PowerShellCore / EventID: 4103](#provider-powershellcore--eventid-4103-1)

## Description

TBD

## Event Source(s)

```yml
Provider: Microsoft-Windows-PowerShell
Channel: Microsoft-Windows-PowerShell/Operational
EventID: 4104
```

```yml
Provider: PowerShellCore
Channel: PowerShellCore/Operational
EventID: 4104
```

## Logging Setup

### Provider: Microsoft-Windows-PowerShell / EventID: 4103

```yml
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On PowerShell Script Block Logging
```

### Provider: PowerShellCore / EventID: 4103

```yml
- Computer Configuration
    - Administrative Templates
        - PowerShell Core
            - Turn On PowerShell Script Block Logging
```

## Event Fields

### Provider: Microsoft-Windows-PowerShell / EventID: 4103

```yml
- MessageNumber
- MessageTotal
- ScriptBlockText
- ScriptBlockId
- Path
```

### Provider: PowerShellCore / EventID: 4103

```yml
- MessageNumber
- MessageTotal
- ScriptBlockText
- ScriptBlockId
- Path
```
