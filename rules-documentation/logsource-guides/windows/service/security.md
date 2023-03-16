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
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4731, 4732, 4733, 4734, 4735, 4764, 4799, 4727, 4737, 4728, 4729, 4730, 4754, 4755, 4756, 4757, 4758](#provider-microsoft-windows-security-auditing--eventids-4731-4732-4733-4734-4735-4764-4799-4727-4737-4728-4729-4730-4754-4755-4756-4757-4758)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 4798, 5376, 5377](#provider-microsoft-windows-security-auditing--eventids-4720-4722-4723-4724-4725-4726-4738-4740-4765-4766-4767-4780-4781-4794-4798-5376-5377)
    - [Detailed Tracking](#detailed-tracking)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4692, 4693, 4694, 4695](#provider-microsoft-windows-security-auditing--eventids-4692-4693-4694-4695)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 6416, 6419, 6420, 6421, 6422, 6423, 6424](#provider-microsoft-windows-security-auditing--eventids-6416-6419-6420-6421-6422-6423-6424)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4688, 4696](#provider-microsoft-windows-security-auditing--eventids-4688-4696)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4689](#provider-microsoft-windows-security-auditing--eventids-4689)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 5712](#provider-microsoft-windows-security-auditing--eventids-5712)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4703](#provider-microsoft-windows-security-auditing--eventids-4703)
    - [DS Access](#ds-access)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4928, 4929, 4930, 4931, 4934, 4935, 4936, 4937](#provider-microsoft-windows-security-auditing--eventids-4928-4929-4930-4931-4934-4935-4936-4937)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4661, 4662](#provider-microsoft-windows-security-auditing--eventids-4661-4662)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 5136, 5137, 5138, 5139, 5141](#provider-microsoft-windows-security-auditing--eventids-5136-5137-5138-5139-5141)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4932, 4933](#provider-microsoft-windows-security-auditing--eventids-4932-4933)
    - [Logon/Logoff](#logonlogoff)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4625](#provider-microsoft-windows-security-auditing--eventids-4625)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4626](#provider-microsoft-windows-security-auditing--eventids-4626)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4627](#provider-microsoft-windows-security-auditing--eventids-4627)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4978, 4979, 4980, 4981, 4982, 4983, 4984](#provider-microsoft-windows-security-auditing--eventids-4978-4979-4980-4981-4982-4983-4984)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4646, 4650, 4651, 4652, 4653, 4655, 4976, 5049, 5453](#provider-microsoft-windows-security-auditing--eventids-4646-4650-4651-4652-4653-4655-4976-5049-5453)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4977, 5451, 5452](#provider-microsoft-windows-security-auditing--eventids-4977-5451-5452)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4634, 4647](#provider-microsoft-windows-security-auditing--eventids-4634-4647)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4624, 4625, 4648, 4675](#provider-microsoft-windows-security-auditing--eventids-4624-4625-4648-4675)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280](#provider-microsoft-windows-security-auditing--eventids-6272-6273-6274-6275-6276-6277-6278-6279-6280)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633](#provider-microsoft-windows-security-auditing--eventids-4649-4778-4779-4800-4801-4802-4803-5378-5632-5633)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4964, 4672](#provider-microsoft-windows-security-auditing--eventids-4964-4672)
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
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4715, 4719, 4817, 4902, 4906, 4907, 4908, 4912, 4904, 4905](#provider-microsoft-windows-security-auditing--eventids-4715-4719-4817-4902-4906-4907-4908-4912-4904-4905)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4670, 4706, 4707, 4716, 4713, 4717, 4718, 4739, 4864, 4865, 4866, 4867](#provider-microsoft-windows-security-auditing--eventids-4670-4706-4707-4716-4713-4717-4718-4739-4864-4865-4866-4867)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4703, 4704, 4705, 4670, 4911, 4913](#provider-microsoft-windows-security-auditing--eventids-4703-4704-4705-4670-4911-4913)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4709, 4710, 4711, 4712, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047, 5048, 5440, 5441, 5442, 5443, 5444, 5446, 5448, 5449, 5450, 5456, 5457, 5458, 5459, 5460, 5461, 5462, 5463, 5464, 5465, 5466, 5467, 5468, 5471, 5472, 5473, 5474, 5477](#provider-microsoft-windows-security-auditing--eventids-4709-4710-4711-4712-5040-5041-5042-5043-5044-5045-5046-5047-5048-5440-5441-5442-5443-5444-5446-5448-5449-5450-5456-5457-5458-5459-5460-5461-5462-5463-5464-5465-5466-5467-5468-5471-5472-5473-5474-5477)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4956, 4957, 4958](#provider-microsoft-windows-security-auditing--eventids-4944-4945-4946-4947-4948-4949-4950-4951-4952-4953-4954-4956-4957-4958)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4714, 4819, 4826, 4909, 4910, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5447, 6144, 6145](#provider-microsoft-windows-security-auditing--eventids-4714-4819-4826-4909-4910-5063-5064-5065-5066-5067-5068-5069-5070-5447-6144-6145)
    - [Privilege Use](#privilege-use)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985](#provider-microsoft-windows-security-auditing--eventid-4673-4674-4985)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4985](#provider-microsoft-windows-security-auditing--eventid-4985)
      - [Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985](#provider-microsoft-windows-security-auditing--eventid-4673-4674-4985-1)
    - [System](#system)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4960, 4961, 4962, 4963, 4965, 5478, 5479, 5480, 5483, 5484, 5485](#provider-microsoft-windows-security-auditing--eventids-4960-4961-4962-4963-4965-5478-5479-5480-5483-5484-5485)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 5024, 5025, 5027, 5028, 5029, 5030, 5032, 5033, 5034, 5035, 5037, 5058, 5059, 6400, 6401, 6402, 6403, 6404, 6405, 6406, 6407, 6408, 6409](#provider-microsoft-windows-security-auditing--eventids-5024-5025-5027-5028-5029-5030-5032-5033-5034-5035-5037-5058-5059-6400-6401-6402-6403-6404-6405-6406-6407-6408-6409)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4608, 4616, 4621](#provider-microsoft-windows-security-auditing--eventids-4608-4616-4621)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4610, 4611, 4614, 4622, 4697](#provider-microsoft-windows-security-auditing--eventids-4610-4611-4614-4622-4697)
      - [Provider: Microsoft Windows Security Auditing / EventID(s): 4612, 4615, 4618, 4816, 5038, 5056, 5062, 5057, 5060, 5061, 6281, 6410](#provider-microsoft-windows-security-auditing--eventids-4612-4615-4618-4816-5038-5056-5062-5057-5060-5061-6281-6410)
    - [Global Object Access Auditing](#global-object-access-auditing)
  - [Full Event(s) List](#full-events-list)
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

Subcategory GUID: {0CCE923F-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9242-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9240-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9241-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9239-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9236-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9238-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE923A-69AE-11D9-BED3-505054503030}

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4731, 4732, 4733, 4734, 4735, 4764, 4799, 4727, 4737, 4728, 4729, 4730, 4754, 4755, 4756, 4757, 4758

Subcategory GUID: {0CCE9237-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9235-69AE-11D9-BED3-505054503030}

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4692, 4693, 4694, 4695

Subcategory GUID: {0CCE922D-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-dpapi-activity)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit DPAPI Activity
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 6416, 6419, 6420, 6421, 6422, 6423, 6424

Subcategory GUID: {0CCE9248-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-pnp-activity)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit PNP Activity
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4688, 4696

Subcategory GUID: {0CCE922B-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4689

Subcategory GUID: {0CCE922C-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-termination)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Process Termination
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 5712

Subcategory GUID: {0CCE922E-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-rpc-events)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit RPC Events
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4703

Subcategory GUID: {0CCE924A-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-token-right-adjusted)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Detailed Tracking
                        - Audit Token Right Adjusted
                            - Success and Failure
```

### DS Access

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4928, 4929, 4930, 4931, 4934, 4935, 4936, 4937

Subcategory GUID: {0CCE923E-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-directory-service-replication)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Detailed Directory Service Replication
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4661, 4662

Subcategory GUID: {0CCE923B-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-access)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Access
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 5136, 5137, 5138, 5139, 5141

Subcategory GUID: {0CCE923C-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-changes)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Changes
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4932, 4933

Subcategory GUID: {0CCE923D-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-replication)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - DS Access
                        - Audit Directory Service Replication
                            - Success and Failure
```

### Logon/Logoff

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4625

Subcategory GUID: {0CCE9217-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-account-lockout)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Account Lockout
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4626

Subcategory GUID: {0CCE9247-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-device-claims)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit User/Device Claims
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4627

Subcategory GUID: {0CCE9249-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-group-membership)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Group Membership
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4978, 4979, 4980, 4981, 4982, 4983, 4984

Subcategory GUID: {0CCE921A-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-extended-mode)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Extended Mode
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4646, 4650, 4651, 4652, 4653, 4655, 4976, 5049, 5453

Subcategory GUID: {0CCE9218-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-main-mode)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Main Mode
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4977, 5451, 5452

Subcategory GUID: {0CCE9219-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-quick-mode)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit IPsec Quick Mode
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4634, 4647

Subcategory GUID: {0CCE9216-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logoff)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Logoff
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4624, 4625, 4648, 4675

Subcategory GUID: {0CCE9215-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Logon
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280

Subcategory GUID: {0CCE9243-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-network-policy-server)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Network Policy Server
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633

Subcategory GUID: {0CCE921C-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-logonlogoff-events)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Other Logon/Logoff Events
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4964, 4672

Subcategory GUID: {0CCE921B-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-special-logon)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Logon/Logoff
                        - Audit Special Logon
                            - Success and Failure
```

### Object Access

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4665, 4666, 4667, 4668

Subcategory GUID: {0CCE9222-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9221-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9244-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9224-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE921D-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9226-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9225-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9223-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE921F-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9227-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE921E-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9245-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9220-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9246-69AE-11D9-BED3-505054503030}

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4715, 4719, 4817, 4902, 4906, 4907, 4908, 4912, 4904, 4905

Subcategory GUID: {0CCE922F-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-audit-policy-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Audit Policy Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4670, 4706, 4707, 4716, 4713, 4717, 4718, 4739, 4864, 4865, 4866, 4867

Subcategory GUID: {0CCE9230-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-authentication-policy-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Authentication Policy Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4703, 4704, 4705, 4670, 4911, 4913

Subcategory GUID: {0CCE9231-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-authorization-policy-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Authorization Policy Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4709, 4710, 4711, 4712, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047, 5048, 5440, 5441, 5442, 5443, 5444, 5446, 5448, 5449, 5450, 5456, 5457, 5458, 5459, 5460, 5461, 5462, 5463, 5464, 5465, 5466, 5467, 5468, 5471, 5472, 5473, 5474, 5477

Subcategory GUID: {0CCE9233-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-policy-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Filtering Platform Policy Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4956, 4957, 4958

Subcategory GUID: {0CCE9232-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-mpssvc-rule-level-policy-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit MPSSVC Rule-Level Policy Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4714, 4819, 4826, 4909, 4910, 5063, 5064, 5065, 5066, 5067, 5068, 5069, 5070, 5447, 6144, 6145

Subcategory GUID: {0CCE9234-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-policy-change-events)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - Policy Change
                        - Audit Other Policy Change Events
                            - Success and Failure
```

### Privilege Use

#### Provider: Microsoft Windows Security Auditing / EventID: 4673, 4674, 4985

Subcategory GUID: {0CCE9229-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE922A-69AE-11D9-BED3-505054503030}

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

Subcategory GUID: {0CCE9228-69AE-11D9-BED3-505054503030}

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

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4960, 4961, 4962, 4963, 4965, 5478, 5479, 5480, 5483, 5484, 5485

Subcategory GUID: {0CCE9213-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-ipsec-driver)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit IPsec Driver
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 5024, 5025, 5027, 5028, 5029, 5030, 5032, 5033, 5034, 5035, 5037, 5058, 5059, 6400, 6401, 6402, 6403, 6404, 6405, 6406, 6407, 6408, 6409

Subcategory GUID: {0CCE9214-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-system-events)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Other System Events
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4608, 4616, 4621

Subcategory GUID: {0CCE9210-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-state-change)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Security State Change
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4610, 4611, 4614, 4622, 4697

Subcategory GUID: {0CCE9211-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-system-extension)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit Security System Extension
                            - Success and Failure
```

#### Provider: Microsoft Windows Security Auditing / EventID(s): 4612, 4615, 4618, 4816, 5038, 5056, 5062, 5057, 5060, 5061, 6281, 6410

Subcategory GUID: {0CCE9212-69AE-11D9-BED3-505054503030}

[Learn More](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-system-integrity)

```yml
- Computer Configuration
    - Windows Settings
        - Security Settings
            - Advanced Audit Policy Configuration
                - System Audit Policies - Local Group Policy Object
                    - System
                        - Audit System Integrity
                            - Success and Failure
```

### Global Object Access Auditing

TBD

## Full Event(s) List

<details>

<summary>Expand</summary>

- 1100(S): The event logging service has shut down.
- 1102(S): The audit log was cleared.
- 1104(S): The security log is now full.
- 1105(S): Event log automatic backup.
- 1108(S): The event logging service encountered an error while processing an incoming event published from %1
- 4608(S): Windows is starting up.
- 4610(S): An authentication package has been loaded by the Local Security Authority.
- 4611(S): A trusted logon process has been registered with the Local Security Authority.
- 4612(S): Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.
- 4614(S): A notification package has been loaded by the Security Account Manager.
- 4615(S): Invalid use of LPC port.
- 4616(S): The system time was changed.
- 4618(S): A monitored security event pattern has occurred.
- 4621(S): Administrator recovered system from CrashOnAuditFail.
- 4622(S): A security package has been loaded by the Local Security Authority.
- 4624(S): An account was successfully logged on.
- 4625(F): An account failed to log on.
- 4625(F): An account failed to log on.
- 4626(S): User/Device claims information.
- 4627(S): Group membership information.
- 4634(S): An account was logged off.
- 4646(S): Security ID: %1
- 4647(S): User initiated logoff.
- 4648(S): A logon was attempted using explicit credentials.
- 4649(S): A replay attack was detected.
- 4650(S): An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.
- 4651(S): An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.
- 4652(F): An IPsec Main Mode negotiation failed.
- 4653(F): An IPsec Main Mode negotiation failed.
- 4655(S): An IPsec Main Mode security association ended.
- 4656(S, F): A handle to an object was requested.
- 4656(S, F): A handle to an object was requested.
- 4656(S, F): A handle to an object was requested.
- 4656(S, F): A handle to an object was requested.
- 4657(S): A registry value was modified.
- 4658(S): The handle to an object was closed.
- 4658(S): The handle to an object was closed.
- 4658(S): The handle to an object was closed.
- 4658(S): The handle to an object was closed.
- 4658(S): The handle to an object was closed.
- 4658(S): The handle to an object was closed. For a description of the event, see 4658(S): The handle to an object was closed. in the Audit File System subcategory. This event doesn't generate in the Audit Handle Manipulation subcategory, but you can use this subcategory to enable it.
- 4660(S): An object was deleted.
- 4660(S): An object was deleted.
- 4660(S): An object was deleted.
- 4661(S, F): A handle to an object was requested.
- 4661(S, F): A handle to an object was requested.
- 4662(S, F): An operation was performed on an object.
- 4663(S): An attempt was made to access an object.
- 4663(S): An attempt was made to access an object.
- 4663(S): An attempt was made to access an object.
- 4663(S): An attempt was made to access an object.
- 4664(S): An attempt was made to create a hard link.
- 4665: An attempt was made to create an application client context.
- 4666: An application attempted an operation.
- 4667: An application client context was deleted.
- 4668: An application was initialized.
- 4670(S): Permissions on an object were changed
- 4670(S): Permissions on an object were changed.
- 4670(S): Permissions on an object were changed.
- 4670(S): Permissions on an object were changed.
- 4671(-): An application attempted to access a blocked ordinal through the TBS.
- 4672(S): Special privileges assigned to new logon.
- 4673(S, F): A privileged service was called.
- 4673(S, F): A privileged service was called.
- 4674(S, F): An operation was attempted on a privileged object.
- 4674(S, F): An operation was attempted on a privileged object.
- 4675(S): SIDs were filtered.
- 4688(S): A new process has been created.
- 4689(S): A process has exited.
- 4690(S): An attempt was made to duplicate a handle to an object.
- 4691(S): Indirect access to an object was requested.
- 4692(S, F): Backup of data protection master key was attempted.
- 4693(S, F): Recovery of data protection master key was attempted.
- 4694(S, F): Protection of auditable protected data was attempted.
- 4695(S, F): Unprotection of auditable protected data was attempted.
- 4696(S): A primary token was assigned to process.
- 4697(S): A service was installed in the system.
- 4698(S): A scheduled task was created.
- 4699(S): A scheduled task was deleted.
- 4700(S): A scheduled task was enabled.
- 4701(S): A scheduled task was disabled.
- 4702(S): A scheduled task was updated.
- 4703(S): A user right was adjusted.
- 4703(S): A user right was adjusted.
- 4704(S): A user right was assigned.
- 4705(S): A user right was removed.
- 4706(S): A new trust was created to a domain.
- 4707(S): A trust to a domain was removed.
- 4709(S): IPsec Services was started.
- 4710(S): IPsec Services was disabled.
- 4711(S): May contain any one of the following:
- 4712(F): IPsec Services encountered a potentially serious failure.
- 4713(S): Kerberos policy was changed.
- 4714(S): Encrypted data recovery policy was changed.
- 4715(S): The audit policy (SACL) on an object was changed.
- 4716(S): Trusted domain information was modified.
- 4717(S): System security access was granted to an account.
- 4718(S): System security access was removed from an account.
- 4719(S): System audit policy was changed.
- 4720(S): A user account was created.
- 4722(S): A user account was enabled.
- 4723(S, F): An attempt was made to change an account's password.
- 4724(S, F): An attempt was made to reset an account's password.
- 4725(S): A user account was disabled.
- 4726(S): A user account was deleted.
- 4727(S): A security-enabled global group was created. See event 4731: A security-enabled local group was created. Event 4727 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4728(S): A member was added to a security-enabled global group. See event 4732: A member was added to a security-enabled local group. Event 4728 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4729(S): A member was removed from a security-enabled global group. See event 4733: A member was removed from a security-enabled local group. Event 4729 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4730(S): A security-enabled global group was deleted. See event 4734: A security-enabled local group was deleted. Event 4730 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4731(S): A security-enabled local group was created.
- 4732(S): A member was added to a security-enabled local group.
- 4733(S): A member was removed from a security-enabled local group.
- 4734(S): A security-enabled local group was deleted.
- 4735(S): A security-enabled local group was changed.
- 4737(S): A security-enabled global group was changed. See event 4735: A security-enabled local group was changed. Event 4737 is the same, but it is generated for a global security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4738(S): A user account was changed.
- 4739(S): Domain Policy was changed.
- 4740(S): A user account was locked out.
- 4741(S): A computer account was created.
- 4742(S): A computer account was changed.
- 4743(S): A computer account was deleted.
- 4744(S): A security-disabled local group was created. See event 4749: A security-disabled global group was created. Event 4744 is the same, except it is generated for a local distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4745(S): A security-disabled local group was changed. See event 4750: A security-disabled global group was changed. Event 4745 is the same, except it is generated for a local distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4746(S): A member was added to a security-disabled local group. See event 4751: A member was added to a security-disabled global group. Event 4746 is the same, except it is generated for a local distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4747(S): A member was removed from a security-disabled local group. See event 4752: A member was removed from a security-disabled global group. Event 4747 is the same, except it is generated for a local distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4748(S): A security-disabled local group was deleted. See event 4753: A security-disabled global group was deleted. Event 4748 is the same, except it is generated for a local distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4749(S): A security-disabled global group was created.
- 4750(S): A security-disabled global group was changed.
- 4751(S): A member was added to a security-disabled global group.
- 4752(S): A member was removed from a security-disabled global group.
- 4753(S): A security-disabled global group was deleted.
- 4754(S): A security-enabled universal group was created. See event 4731: A security-enabled local group was created. Event 4754 is the same, but it is generated for a universal security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4755(S): A security-enabled universal group was changed. See event 4735: A security-enabled local group was changed. Event 4737 is the same, but it is generated for a universal security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4756(S): A member was added to a security-enabled universal group. See event 4732: A member was added to a security-enabled local group. Event 4756 is the same, but it is generated for a universal security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4757(S): A member was removed from a security-enabled universal group. See event 4733: A member was removed from a security-enabled local group. Event 4757 is the same, but it is generated for a universal security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4758(S): A security-enabled universal group was deleted. See event 4734: A security-enabled local group was deleted. Event 4758 is the same, but it is generated for a universal security group instead of a local security group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4759(S): A security-disabled universal group was created. See event 4749: A security-disabled global group was created. Event 4759 is the same, except it is generated for a universal distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4760(S): A security-disabled universal group was changed. See event 4750: A security-disabled global group was changed. Event 4760 is the same, except it is generated for a universal distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4761(S): A member was added to a security-disabled universal group. See event 4751: A member was added to a security-disabled global group. Event 4761 is the same, except it is generated for a universal distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4762(S): A member was removed from a security-disabled universal group. See event 4752: A member was removed from a security-disabled global group. Event 4762 is the same, except it is generated for a universal distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4763(S): A security-disabled universal group was deleted. See event 4753: A security-disabled global group was deleted. Event 4763 is the same, except it is generated for a universal distribution group instead of a global distribution group. All event fields, XML, and recommendations are the same. The type of group is the only difference.
- 4764(S): A group's type was changed.
- 4765(S): SID History was added to an account.
- 4766(F): An attempt to add SID History to an account failed.
- 4767(S): A user account was unlocked.
- 4768(S, F): A Kerberos authentication ticket (TGT) was requested.
- 4769(S, F): A Kerberos service ticket was requested.
- 4770(S): A Kerberos service ticket was renewed.
- 4771(F): Kerberos pre-authentication failed.
- 4772(F): A Kerberos authentication ticket request failed.
- 4773(F): A Kerberos service ticket request failed.
- 4774(S, F): An account was mapped for logon.
- 4775(F): An account could not be mapped for logon.
- 4776(S, F): The computer attempted to validate the credentials for an account.
- 4777(F): The domain controller failed to validate the credentials for an account.
- 4778(S): A session was reconnected to a Window Station.
- 4779(S): A session was disconnected from a Window Station.
- 4780(S): The ACL was set on accounts which are members of administrators groups.
- 4781(S): The name of an account was changed.
- 4782(S): The password hash of an account was accessed.
- 4783(S): A basic application group was created.
- 4784(S): A basic application group was changed.
- 4785(S): A member was added to a basic application group.
- 4786(S): A member was removed from a basic application group.
- 4787(S): A non-member was added to a basic application group.
- 4788(S): A non-member was removed from a basic application group.
- 4789(S): A basic application group was deleted.
- 4790(S): An LDAP query group was created.
- 4791(S): An LDAP query group was changed.
- 4792(S): An LDAP query group was deleted.
- 4793(S): The Password Policy Checking API was called.
- 4794(S, F): An attempt was made to set the Directory Services Restore Mode administrator password.
- 4798(S): A user's local group membership was enumerated.
- 4799(S): A security-enabled local group membership was enumerated.
- 4800(S): The workstation was locked.
- 4801(S): The workstation was unlocked.
- 4802(S): The screen saver was invoked.
- 4803(S): The screen saver was dismissed.
- 4816(S): RPC detected an integrity violation while decrypting an incoming message.
- 4817(S): Auditing settings on object were changed.
- 4818(S): Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy.
- 4819(S): Central Access Policies on the machine have been changed.
- 4826(S): Boot Configuration Data loaded.
- 4864(S): A namespace collision was detected.
- 4865(S): A trusted forest information entry was added.
- 4866(S): A trusted forest information entry was removed.
- 4867(S): A trusted forest information entry was modified.
- 4868: The certificate manager denied a pending certificate request.
- 4869: Certificate Services received a resubmitted certificate request.
- 4870: Certificate Services revoked a certificate.
- 4871: Certificate Services received a request to publish the certificate revocation list (CRL).
- 4872: Certificate Services published the certificate revocation list (CRL).
- 4873: A certificate request extension changed.
- 4874: One or more certificate request attributes changed.
- 4875: Certificate Services received a request to shut down.
- 4876: Certificate Services backup started.
- 4877: Certificate Services backup completed.
- 4878: Certificate Services restore started.
- 4879: Certificate Services restore completed.
- 4880: Certificate Services started.
- 4881: Certificate Services stopped.
- 4882: The security permissions for Certificate Services changed.
- 4883: Certificate Services retrieved an archived key.
- 4884: Certificate Services imported a certificate into its database.
- 4885: The audit filter for Certificate Services changed.
- 4886: Certificate Services received a certificate request.
- 4887: Certificate Services approved a certificate request and issued a certificate.
- 4888: Certificate Services denied a certificate request.
- 4889: Certificate Services set the status of a certificate request to pending.
- 4890: The certificate manager settings for Certificate Services changed.
- 4891: A configuration entry changed in Certificate Services.
- 4892: A property of Certificate Services changed.
- 4893: Certificate Services archived a key.
- 4894: Certificate Services imported and archived a key.
- 4895: Certificate Services published the CA certificate to Active Directory Domain Services.
- 4896: One or more rows have been deleted from the certificate database.
- 4897: Role separation enabled.
- 4898: Certificate Services loaded a template.
- 4902(S): The Per-user audit policy table was created.
- 4904(S): An attempt was made to register a security event source.
- 4905(S): An attempt was made to unregister a security event source.
- 4906(S): The CrashOnAuditFail value has changed.
- 4907(S): Auditing settings on object were changed.
- 4908(S): Special Groups Logon table modified.
- 4909(-): The local policy settings for the TBS were changed.
- 4910(-): The group policy settings for the TBS were changed.
- 4911(S): Resource attributes of the object were changed.
- 4912(S): Per User Audit Policy was changed.
- 4913(S): Central Access Policy on the object was changed.
- 4928(S, F): An Active Directory replica source naming context was established.
- 4929(S, F): An Active Directory replica source naming context was removed.
- 4930(S, F): An Active Directory replica source naming context was modified.
- 4931(S, F): An Active Directory replica destination naming context was modified.
- 4932(S): Synchronization of a replica of an Active Directory naming context has begun.
- 4933(S, F): Synchronization of a replica of an Active Directory naming context has ended.
- 4934(S): Attributes of an Active Directory object were replicated.
- 4935(F): Replication failure begins.
- 4936(S): Replication failure ends.
- 4937(S): A lingering object was removed from a replica.
- 4944(S): The following policy was active when the Windows Firewall started.
- 4945(S): A rule was listed when the Windows Firewall started.
- 4946(S): A change has been made to Windows Firewall exception list. A rule was added.
- 4947(S): A change has been made to Windows Firewall exception list. A rule was modified.
- 4948(S): A change has been made to Windows Firewall exception list. A rule was deleted.
- 4949(S): Windows Firewall settings were restored to the default values.
- 4950(S): A Windows Firewall setting has changed.
- 4951(F): A rule has been ignored because its major version number was not recognized by Windows Firewall.
- 4952(F): Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced.
- 4953(F): A rule has been ignored by Windows Firewall because it could not parse the rule.
- 4954(S): Windows Firewall Group Policy settings have changed. The new settings have been applied.
- 4956(S): Windows Firewall has changed the active profile.
- 4957(F): Windows Firewall did not apply the following rule:
- 4958(F): Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer:
- 4960(S): IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.
- 4961(S): IPsec dropped an inbound packet that failed a replay check. If this problem persists, it could indicate a replay attack against this computer.
- 4962(S): IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.
- 4963(S): IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.
- 4964(S): Special groups have been assigned to a new logon.
- 4965(S): IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist, verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case, if connectivity is not impeded, then these events can be ignored.
- 4976(S): During Main Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.
- 4977(S): During Quick Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.
- 4978(S): During Extended Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.
- 4979(S): IPsec Main Mode and Extended Mode security associations were established.
- 4980(S): IPsec Main Mode and Extended Mode security associations were established.
- 4981(S): IPsec Main Mode and Extended Mode security associations were established.
- 4982(S): IPsec Main Mode and Extended Mode security associations were established.
- 4983(S): An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
- 4984(S): An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
- 4985(S): The state of a transaction has changed.
- 4985(S): The state of a transaction has changed.
- 4985(S): The state of a transaction has changed.
- 4985(S): The state of a transaction has changed.
- 5024(S): The Windows Firewall Service has started successfully.
- 5025(S): The Windows Firewall Service has been stopped.
- 5027(F): The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.
- 5028(F): The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.
- 5029(F): The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.
- 5030(F): The Windows Firewall Service failed to start.
- 5031(F): The Windows Firewall Service blocked an application from accepting incoming connections on the network.
- 5032(F): Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.
- 5033(S): The Windows Firewall Driver has started successfully.
- 5034(S): The Windows Firewall Driver was stopped.
- 5035(F): The Windows Firewall Driver failed to start.
- 5037(F): The Windows Firewall Driver detected critical runtime error. Terminating.
- 5038(F): Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.
- 5039(-): A registry key was virtualized.
- 5040(S): A change has been made to IPsec settings. An Authentication Set was added.
- 5041(S): A change has been made to IPsec settings. An Authentication Set was modified.
- 5042(S): A change has been made to IPsec settings. An Authentication Set was deleted.
- 5043(S): A change has been made to IPsec settings. A Connection Security Rule was added.
- 5044(S): A change has been made to IPsec settings. A Connection Security Rule was modified.
- 5045(S): A change has been made to IPsec settings. A Connection Security Rule was deleted.
- 5046(S): A change has been made to IPsec settings. A Crypto Set was added.
- 5047(S): A change has been made to IPsec settings. A Crypto Set was modified.
- 5048(S): A change has been made to IPsec settings. A Crypto Set was deleted.
- 5049(S): An IPsec Security Association was deleted.
- 5051(-): A file was virtualized.
- 5056(S): A cryptographic self-test was performed.
- 5057(F): A cryptographic primitive operation failed.
- 5058(S, F): Key file operation.
- 5059(S, F): Key migration operation.
- 5060(F): Verification operation failed.
- 5061(S, F): Cryptographic operation.
- 5062(S): A kernel-mode cryptographic self-test was performed.
- 5063(S, F): A cryptographic provider operation was attempted.
- 5064(S, F): A cryptographic context operation was attempted.
- 5065(S, F): A cryptographic context modification was attempted.
- 5066(S, F): A cryptographic function operation was attempted.
- 5067(S, F): A cryptographic function modification was attempted.
- 5068(S, F): A cryptographic function provider operation was attempted.
- 5069(S, F): A cryptographic function property operation was attempted.
- 5070(S, F): A cryptographic function property modification was attempted.
- 5136(S): A directory service object was modified.
- 5137(S): A directory service object was created.
- 5138(S): A directory service object was undeleted.
- 5139(S): A directory service object was moved.
- 5140(S, F): A network share object was accessed.
- 5141(S): A directory service object was deleted.
- 5142(S): A network share object was added.
- 5143(S): A network share object was modified.
- 5144(S): A network share object was deleted.
- 5145(S, F): A network share object was checked to see whether client can be granted desired access.
- 5148(F): The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.
- 5149(F): The DoS attack has subsided and normal processing is being resumed.
- 5150(-): The Windows Filtering Platform blocked a packet.
- 5151(-): A more restrictive Windows Filtering Platform filter has blocked a packet.
- 5152(F): The Windows Filtering Platform blocked a packet.
- 5153(S): A more restrictive Windows Filtering Platform filter has blocked a packet.
- 5154(S): The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.
- 5155(F): The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.
- 5156(S): The Windows Filtering Platform has permitted a connection.
- 5157(F): The Windows Filtering Platform has blocked a connection.
- 5158(S): The Windows Filtering Platform has permitted a bind to a local port.
- 5159(F): The Windows Filtering Platform has blocked a bind to a local port.
- 5168(F): SPN check for SMB/SMB2 failed.
- 5376(S): Credential Manager credentials were backed up.
- 5377(S): Credential Manager credentials were restored from a backup.
- 5378(F): The requested credentials delegation was disallowed by policy.
- 5440(S): The following callout was present when the Windows Filtering Platform Base Filtering Engine started.
- 5441(S): The following filter was present when the Windows Filtering Platform Base Filtering Engine started.
- 5442(S): The following provider was present when the Windows Filtering Platform Base Filtering Engine started.
- 5443(S): The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.
- 5444(S): The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started.
- 5446(S): A Windows Filtering Platform callout has been changed.
- 5447(S): A Windows Filtering Platform filter has been changed.
- 5448(S): A Windows Filtering Platform provider has been changed.
- 5449(S): A Windows Filtering Platform provider context has been changed.
- 5450(S): A Windows Filtering Platform sub-layer has been changed.
- 5451(S): An IPsec Quick Mode security association was established.
- 5452(S): An IPsec Quick Mode security association ended.
- 5453(S): An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.
- 5456(S): PAStore Engine applied Active Directory storage IPsec policy on the computer.
- 5457(F): PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.
- 5458(S): PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.
- 5459(F): PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.
- 5460(S): PAStore Engine applied local registry storage IPsec policy on the computer.
- 5461(F): PAStore Engine failed to apply local registry storage IPsec policy on the computer.
- 5462(F): PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem.
- 5463(S): PAStore Engine polled for changes to the active IPsec policy and detected no changes.
- 5464(S): PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services.
- 5465(S): PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully.
- 5466(F): PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied.
- 5467(F): PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy. The cached copy of the Active Directory IPsec policy is no longer being used.
- 5468(S): PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used.
- 5471(S): PAStore Engine loaded local storage IPsec policy on the computer.
- 5472(F): PAStore Engine failed to load local storage IPsec policy on the computer.
- 5473(S): PAStore Engine loaded directory storage IPsec policy on the computer.
- 5474(F): PAStore Engine failed to load directory storage IPsec policy on the computer.
- 5477(F): PAStore Engine failed to add quick mode filter.
- 5478(S): IPsec Services has started successfully.
- 5479(S): IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5480(F): IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- 5483(F): IPsec Services failed to initialize RPC server. IPsec Services could not be started.
- 5484(F): IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5485(F): IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- 5632(S): A request was made to authenticate to a wireless network.
- 5633(S): A request was made to authenticate to a wired network.
- 5712(S): A Remote Procedure Call (RPC) was attempted.
- 5888(S): An object in the COM+ Catalog was modified.
- 5889(S): An object was deleted from the COM+ Catalog.
- 5890(S): An object was added to the COM+ Catalog.
- 6144(S): Security policy in the group policy objects has been applied successfully.
- 6145(F): One or more errors occurred while processing security policy in the group policy objects.
- 6272: Network Policy Server granted access to a user.
- 6273: Network Policy Server denied access to a user.
- 6274: Network Policy Server discarded the request for a user.
- 6275: Network Policy Server discarded the accounting request for a user.
- 6276: Network Policy Server quarantined a user.
- 6277: Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.
- 6278: Network Policy Server granted full access to a user because the host met the defined health policy.
- 6279: Network Policy Server locked the user account due to repeated failed authentication attempts.
- 6280: Network Policy Server unlocked the user account.
- 6281(F): Code Integrity determined that the page hashes of an image file are not valid. The file could be improperly signed without page hashes or corrupt due to unauthorized modification. The invalid hashes could indicate a potential disk device error.
- 6400(-): BranchCache: Received an incorrectly formatted response while discovering availability of content.
- 6401(-): BranchCache: Received invalid data from a peer. Data discarded.
- 6402(-): BranchCache: The message to the hosted cache offering it data is incorrectly formatted.
- 6403(-): BranchCache: The hosted cache sent an incorrectly formatted response to the client.
- 6404(-): BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.
- 6405(-): BranchCache: %2 instance(s) of event id %1 occurred.
- 6406(-): %1 registered to Windows Firewall to control filtering for the following: %2
- 6407(-): 1%
- 6408(-): Registered product %1 failed and Windows Firewall is now controlling the filtering for %2
- 6409(-): BranchCache: A service connection point object could not be parsed.
- 6410(F): Code integrity determined that a file does not meet the security requirements to load into a process.
- 6416(S): A new external device was recognized by the System
- 6419(S): A request was made to disable a device
- 6420(S): A device was disabled.
- 6421(S): A request was made to enable a device.
- 6422(S): A device was enabled.
- 6423(S): The installation of this device is forbidden by system policy.
- 6424(S): The installation of this device was allowed, after having previously been forbidden by policy.

</details>

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
