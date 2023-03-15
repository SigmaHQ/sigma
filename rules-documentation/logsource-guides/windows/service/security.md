# service: security

ID: dfd8c0f4-e6ad-4e07-b91b-f2fca0ddef64

## Content

- [service: security](#service-security)
  - [Content](#content)
  - [Description](#description)
  - [Event Source(s)](#event-sources)
  - [Logging Setup](#logging-setup)
    - [Account Logon](#account-logon)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4774, 4775, 4776, 4777](#provider-microsoft-windows-security-auditing--eventids-4774-4775-4776-4777)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4768, 4771, 4772](#provider-microsoft-windows-security-auditing--eventids-4768-4771-4772)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4769, 4770, 4773](#provider-microsoft-windows-security-auditing--eventids-4769-4770-4773)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): TBD](#provider-microsoft-windows-security-auditing--eventids-tbd)
    - [Account Management](#account-management)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4783, 4784, 4785, 4786, 4787, 4788, 4789, 4790, 4791, 4792](#provider-microsoft-windows-security-auditing--eventids-4783-4784-4785-4786-4787-4788-4789-4790-4791-4792)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4741, 4742, 4743](#provider-microsoft-windows-security-auditing--eventids-4741-4742-4743)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4749, 4750, 4751, 4752, 4753](#provider-microsoft-windows-security-auditing--eventids-4749-4750-4751-4752-4753)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4782, 4793](#provider-microsoft-windows-security-auditing--eventids-4782-4793)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4731, 4732, 4733, 4734, 4735, 4764, 4799](#provider-microsoft-windows-security-auditing--eventids-4731-4732-4733-4734-4735-4764-4799)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798, 5376, 5377](#provider-microsoft-windows-security-auditing--eventids-4720-4722-4723-4724-4725-4726-4738-4740-4765-4766-4767-4780-4781-4794-4798-5376-5377)
    - [Detailed Tracking](#detailed-tracking)
    - [DS Access](#ds-access)
    - [Logon/Logoff](#logonlogoff)
    - [Object Access](#object-access)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4665, 4666, 4667, 4668](#provider-microsoft-windows-security-auditing--eventids-4665-4666-4667-4668)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4868, 4869, 4870, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4886, 4887, 4888, 4889, 4890, 4891, 4892, 4893, 4894, 4895, 4896, 4897, 4898](#provider-microsoft-windows-security-auditing--eventids-4868-4869-4870-4871-4872-4873-4874-4875-4876-4877-4878-4879-4880-4881-4882-4883-4884-4885-4886-4887-4888-4889-4890-4891-4892-4893-4894-4895-4896-4897-4898)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 5145](#provider-microsoft-windows-security-auditing--eventids-5145)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 5140, 5142, 5143, 5144, 5168](#provider-microsoft-windows-security-auditing--eventids-5140-5142-5143-5144-5168)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4656, 4658, 4660, 4663, 4664, 4670, 4985, 5051](#provider-microsoft-windows-security-auditing--eventids-4656-4658-4660-4663-4664-4670-4985-5051)
      - [Provider: Microsoft Windows Security Auditing / EventID: 5031, 5150, 5151, 5154, 5155, 5156, 5157, 5158, 5159](#provider-microsoft-windows-security-auditing--eventid-5031-5150-5151-5154-5155-5156-5157-5158-5159)
      - [Provider: Microsoft Windows Security Auditing / EventID: 5152, 5153](#provider-microsoft-windows-security-auditing--eventid-5152-5153)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4658, 4690](#provider-microsoft-windows-security-auditing--eventid-4658-4690)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4656, 4658, 4660, 4663](#provider-microsoft-windows-security-auditing--eventid-4656-4658-4660-4663)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4671, 4691, 4698, 4699, 4700, 4701, 4702, 5148 ,5149, 5888, 5889, 5890](#provider-microsoft-windows-security-auditing--eventid-4671-4691-4698-4699-4700-4701-4702-5148-5149-5888-5889-5890)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4656, 4657, 4658, 4660, 4663, 4670, 5039](#provider-microsoft-windows-security-auditing--eventid-4656-4657-4658-4660-4663-4670-5039)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4656, 4658, 4663](#provider-microsoft-windows-security-auditing--eventid-4656-4658-4663)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4661](#provider-microsoft-windows-security-auditing--eventid-4661)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4818](#provider-microsoft-windows-security-auditing--eventid-4818)
    - [Policy Change](#policy-change)
    - [Privilege Use](#privilege-use)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985](#provider-microsoft-windows-security-auditing--eventid-4673-4674-4985)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4985](#provider-microsoft-windows-security-auditing--eventid-4985)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985](#provider-microsoft-windows-security-auditing--eventid-4673-4674-4985-1)
    - [System](#system)
    - [Global Object Access Auditing](#global-object-access-auditing)
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

### Account Logon

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4774, 4775, 4776, 4777

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-credential-validation)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4768, 4771, 4772

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4769, 4770, 4773

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): TBD

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-account-logon-events)

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

### Account Management

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4783, 4784, 4785, 4786, 4787, 4788, 4789, 4790, 4791, 4792

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-application-group-management)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4741, 4742, 4743

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-computer-account-management)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4749, 4750, 4751, 4752, 4753

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-distribution-group-management)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4782, 4793

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-account-management-events)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4731, 4732, 4733, 4734, 4735, 4764, 4799

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798, 5376, 5377

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management)

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

### Detailed Tracking

TBD

### DS Access

TBD

### Logon/Logoff

TBD

### Object Access

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4665, 4666, 4667, 4668

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-application-generated)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4868, 4869, 4870, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4886, 4887, 4888, 4889, 4890, 4891, 4892, 4893, 4894, 4895, 4896, 4897, 4898

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-certification-services)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 5145

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-file-share)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 5140, 5142, 5143, 5144, 5168

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4656, 4658, 4660, 4663, 4664, 4670, 4985, 5051

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 5031, 5150, 5151, 5154, 5155, 5156, 5157, 5158, 5159

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 5152, 5153

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-packet-drop)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4658, 4690

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-handle-manipulation)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4656, 4658, 4660, 4663

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kernel-object)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4671, 4691, 4698, 4699, 4700, 4701, 4702, 5148 ,5149, 5888, 5889, 5890

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4656, 4657, 4658, 4660, 4663, 4670, 5039

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-registry)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4656, 4658, 4663

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-removable-storage)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4661

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sam)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4818

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-central-access-policy-staging)

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

### Policy Change

TBD

### Privilege Use

#### Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-non-sensitive-privilege-use)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4985

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-privilege-use-events)

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

#### Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sensitive-privilege-use)

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

### System

TBD

### Global Object Access Auditing

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
