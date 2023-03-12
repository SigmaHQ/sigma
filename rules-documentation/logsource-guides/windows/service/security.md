# service: security

ID: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64

## Content

- [service: security](#service-security)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
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

TBD

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
