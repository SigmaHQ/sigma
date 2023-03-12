# service: security

ID: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64

## Content

- [service: security](#service-security)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Source: Microsoft Windows Security Auditing / EventID: 4673](#source-microsoft-windows-security-auditing--eventid-4673)
  - [Event Fields](#event-fields)
    - [Source: Microsoft Windows Security Auditing / EventID: 4673](#source-microsoft-windows-security-auditing--eventid-4673-1)

## Description

## Event Source(s)

```yml
Source: Microsoft Windows Security Auditing
```

## Logging Setup

### Source: Microsoft Windows Security Auditing / EventID: 4673

```yml
TBD
```

## Event Fields

### Source: Microsoft Windows Security Auditing / EventID: 4673

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
