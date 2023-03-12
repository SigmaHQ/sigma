# service: security

ID: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64

## Content

- [service: security](#service-security)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-1)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-2)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-3)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-4)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-5)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-6)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-7)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-8)
    - [Provider: Microsoft Windows Security Auditing / EventID:](#provider-microsoft-windows-security-auditing--eventid-9)
  - [Event Fields](#event-fields)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4627](#provider-microsoft-windows-security-auditing--eventid-4627)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4672](#provider-microsoft-windows-security-auditing--eventid-4672)
    - [Provider: Microsoft Windows Security Auditing / EventID: 4673](#provider-microsoft-windows-security-auditing--eventid-4673)

## Description

TBD

## Event Source(s)

```yml
Provider: Microsoft Windows Security Auditing
```

## Logging Setup

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - 
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Detailed File Share
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit File Share
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Kernel Object
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Other Object Access Events
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit Registry
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Audit SAM
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Privilege Use
                        - Audit Non Sensitive Privilege Use
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Privilege Use
                          - Audit Other Privilege Use Events
```

### Provider: Microsoft Windows Security Auditing / EventID: 

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Object Access
                        - Privilege Use
                          - Audit Sensitive Privilege Use
```


## Event Fields

### Provider: Microsoft Windows Security Auditing / EventID: 4627

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

### Provider: Microsoft Windows Security Auditing / EventID: 4672

```yml
- SubjectUserSid
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- PrivilegeList
```

### Provider: Microsoft Windows Security Auditing / EventID: 4673

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
