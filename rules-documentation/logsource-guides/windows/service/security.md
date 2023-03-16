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

- 1100: The event logging service has shut down.
- 1102: The audit log was cleared.
- 1104: The security log is now full.
- 1105: Event log automatic backup.
- 1108: The event logging service encountered an error while processing an incoming event published from %1
- 4608: Windows is starting up.
- 4610: An authentication package has been loaded by the Local Security Authority.
- 4611: A trusted logon process has been registered with the Local Security Authority.
- 4612: Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.
- 4614: A notification package has been loaded by the Security Account Manager.
- 4615: Invalid use of LPC port.
- 4616: The system time was changed.
- 4618: A monitored security event pattern has occurred.
- 4621: Administrator recovered system from CrashOnAuditFail.
- 4622: A security package has been loaded by the Local Security Authority.
- 4624: An account was successfully logged on.
- 4625: An account failed to log on.
- 4625: An account failed to log on.
- 4626: User/Device claims information.
- 4627: Group membership information.
- 4634: An account was logged off.
- 4646: Security ID: %1
- 4647: User initiated logoff.
- 4648: A logon was attempted using explicit credentials.
- 4649: A replay attack was detected.
- 4650: An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.
- 4651: An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.
- 4652: An IPsec Main Mode negotiation failed.
- 4653: An IPsec Main Mode negotiation failed.
- 4655: An IPsec Main Mode security association ended.
- 4656: A handle to an object was requested.
- 4656: A handle to an object was requested.
- 4656: A handle to an object was requested.
- 4656: A handle to an object was requested.
- 4657: A registry value was modified.
- 4658: The handle to an object was closed.
- 4658: The handle to an object was closed.
- 4658: The handle to an object was closed.
- 4658: The handle to an object was closed.
- 4658: The handle to an object was closed.
- 4658: The handle to an object was closed.
- 4660: An object was deleted.
- 4660: An object was deleted.
- 4660: An object was deleted.
- 4661: A handle to an object was requested.
- 4661: A handle to an object was requested.
- 4662: An operation was performed on an object.
- 4663: An attempt was made to access an object.
- 4663: An attempt was made to access an object.
- 4663: An attempt was made to access an object.
- 4663: An attempt was made to access an object.
- 4664: An attempt was made to create a hard link.
- 4665: An attempt was made to create an application client context.
- 4666: An application attempted an operation.
- 4667: An application client context was deleted.
- 4668: An application was initialized.
- 4670: Permissions on an object were changed
- 4670: Permissions on an object were changed.
- 4670: Permissions on an object were changed.
- 4670: Permissions on an object were changed.
- 4671: An application attempted to access a blocked ordinal through the TBS.
- 4672: Special privileges assigned to new logon.
- 4673: A privileged service was called.
- 4673: A privileged service was called.
- 4674: An operation was attempted on a privileged object.
- 4674: An operation was attempted on a privileged object.
- 4675: SIDs were filtered.
- 4688: A new process has been created.
- 4689: A process has exited.
- 4690: An attempt was made to duplicate a handle to an object.
- 4691: Indirect access to an object was requested.
- 4692: Backup of data protection master key was attempted.
- 4693: Recovery of data protection master key was attempted.
- 4694: Protection of auditable protected data was attempted.
- 4695: Unprotection of auditable protected data was attempted.
- 4696: A primary token was assigned to process.
- 4697: A service was installed in the system.
- 4698: A scheduled task was created.
- 4699: A scheduled task was deleted.
- 4700: A scheduled task was enabled.
- 4701: A scheduled task was disabled.
- 4702: A scheduled task was updated.
- 4703: A user right was adjusted.
- 4703: A user right was adjusted.
- 4704: A user right was assigned.
- 4705: A user right was removed.
- 4706: A new trust was created to a domain.
- 4707: A trust to a domain was removed.
- 4709: IPsec Services was started.
- 4710: IPsec Services was disabled.
- 4711: May contain any one of the following:
- 4712: IPsec Services encountered a potentially serious failure.
- 4713: Kerberos policy was changed.
- 4714: Encrypted data recovery policy was changed.
- 4715: The audit policy (SACL) on an object was changed.
- 4716: Trusted domain information was modified.
- 4717: System security access was granted to an account.
- 4718: System security access was removed from an account.
- 4719: System audit policy was changed.
- 4720: A user account was created.
- 4722: A user account was enabled.
- 4723: An attempt was made to change an account's password.
- 4724: An attempt was made to reset an account's password.
- 4725: A user account was disabled.
- 4726: A user account was deleted.
- 4727: A security-enabled global group was created.
- 4729: A member was removed from a security-enabled global group.
- 4730: A security-enabled global group was deleted.
- 4731: A security-enabled local group was created.
- 4732: A member was added to a security-enabled local group.
- 4733: A member was removed from a security-enabled local group.
- 4734: A security-enabled local group was deleted.
- 4735: A security-enabled local group was changed.
- 4737: A security-enabled global group was changed.
- 4738: A user account was changed.
- 4739: Domain Policy was changed.
- 4740: A user account was locked out.
- 4741: A computer account was created.
- 4742: A computer account was changed.
- 4743: A computer account was deleted.
- 4744: A security-disabled local group was created.
- 4745: A security-disabled local group was changed.
- 4746: A member was added to a security-disabled local group.
- 4747: A member was removed from a security-disabled local group.
- 4748: A security-disabled local group was deleted.
- 4749: A security-disabled global group was created.
- 4750: A security-disabled global group was changed.
- 4751: A member was added to a security-disabled global group.
- 4752: A member was removed from a security-disabled global group.
- 4753: A security-disabled global group was deleted.
- 4754: A security-enabled universal group was created.
- 4755: A security-enabled universal group was changed.
- 4756: A member was added to a security-enabled universal group.
- 4757: A member was removed from a security-enabled universal group.
- 4758: A security-enabled universal group was deleted.
- 4759: A security-disabled universal group was created.
- 4760: A security-disabled universal group was changed.
- 4761: A member was added to a security-disabled universal group.
- 4762: A member was removed from a security-disabled universal group.
- 4763: A security-disabled universal group was deleted.
- 4764: A group's type was changed.
- 4765: SID History was added to an account.
- 4766: An attempt to add SID History to an account failed.
- 4767: A user account was unlocked.
- 4768: A Kerberos authentication ticket (TGT) was requested.
- 4769: A Kerberos service ticket was requested.
- 4770: A Kerberos service ticket was renewed.
- 4771: Kerberos pre-authentication failed.
- 4772: A Kerberos authentication ticket request failed.
- 4773: A Kerberos service ticket request failed.
- 4774: An account was mapped for logon.
- 4775: An account could not be mapped for logon.
- 4776: The computer attempted to validate the credentials for an account.
- 4777: The domain controller failed to validate the credentials for an account.
- 4778: A session was reconnected to a Window Station.
- 4779: A session was disconnected from a Window Station.
- 4780: The ACL was set on accounts which are members of administrators groups.
- 4781: The name of an account was changed.
- 4782: The password hash of an account was accessed.
- 4783: A basic application group was created.
- 4784: A basic application group was changed.
- 4785: A member was added to a basic application group.
- 4786: A member was removed from a basic application group.
- 4787: A non-member was added to a basic application group.
- 4788: A non-member was removed from a basic application group.
- 4789: A basic application group was deleted.
- 4790: An LDAP query group was created.
- 4791: An LDAP query group was changed.
- 4792: An LDAP query group was deleted.
- 4793: The Password Policy Checking API was called.
- 4794: An attempt was made to set the Directory Services Restore Mode administrator password.
- 4798: A user's local group membership was enumerated.
- 4799: A security-enabled local group membership was enumerated.
- 4800: The workstation was locked.
- 4801: The workstation was unlocked.
- 4802: The screen saver was invoked.
- 4803: The screen saver was dismissed.
- 4816: RPC detected an integrity violation while decrypting an incoming message.
- 4817: Auditing settings on object were changed.
- 4818: Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy.
- 4819: Central Access Policies on the machine have been changed.
- 4826: Boot Configuration Data loaded.
- 4864: A namespace collision was detected.
- 4865: A trusted forest information entry was added.
- 4866: A trusted forest information entry was removed.
- 4867: A trusted forest information entry was modified.
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
- 4902: The Per-user audit policy table was created.
- 4904: An attempt was made to register a security event source.
- 4905: An attempt was made to unregister a security event source.
- 4906: The CrashOnAuditFail value has changed.
- 4907: Auditing settings on object were changed.
- 4908: Special Groups Logon table modified.
- 4909: The local policy settings for the TBS were changed.
- 4910: The group policy settings for the TBS were changed.
- 4911: Resource attributes of the object were changed.
- 4912: Per User Audit Policy was changed.
- 4913: Central Access Policy on the object was changed.
- 4928: An Active Directory replica source naming context was established.
- 4929: An Active Directory replica source naming context was removed.
- 4930: An Active Directory replica source naming context was modified.
- 4931: An Active Directory replica destination naming context was modified.
- 4932: Synchronization of a replica of an Active Directory naming context has begun.
- 4933: Synchronization of a replica of an Active Directory naming context has ended.
- 4934: Attributes of an Active Directory object were replicated.
- 4935: Replication failure begins.
- 4936: Replication failure ends.
- 4937: A lingering object was removed from a replica.
- 4944: The following policy was active when the Windows Firewall started.
- 4945: A rule was listed when the Windows Firewall started.
- 4946: A change has been made to Windows Firewall exception list. A rule was added.
- 4947: A change has been made to Windows Firewall exception list. A rule was modified.
- 4948: A change has been made to Windows Firewall exception list. A rule was deleted.
- 4949: Windows Firewall settings were restored to the default values.
- 4950: A Windows Firewall setting has changed.
- 4951: A rule has been ignored because its major version number was not recognized by Windows Firewall.
- 4952: Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall. The other parts of the rule will be enforced.
- 4953: A rule has been ignored by Windows Firewall because it could not parse the rule.
- 4954: Windows Firewall Group Policy settings have changed. The new settings have been applied.
- 4956: Windows Firewall has changed the active profile.
- 4957: Windows Firewall did not apply the following rule:
- 4958: Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer:
- 4960: IPsec dropped an inbound packet that failed an integrity check.
- 4961: IPsec dropped an inbound packet that failed a replay check.
- 4962: IPsec dropped an inbound packet that failed a replay check.
- 4963: IPsec dropped an inbound clear text packet that should have been secured.
- 4964: Special groups have been assigned to a new logon.
- 4965: IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).
- 4976: During Main Mode negotiation, IPsec received an invalid negotiation packet.
- 4977: During Quick Mode negotiation, IPsec received an invalid negotiation packet.
- 4978: During Extended Mode negotiation, IPsec received an invalid negotiation packet.
- 4979: IPsec Main Mode and Extended Mode security associations were established.
- 4980: IPsec Main Mode and Extended Mode security associations were established.
- 4981: IPsec Main Mode and Extended Mode security associations were established.
- 4982: IPsec Main Mode and Extended Mode security associations were established.
- 4983: An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
- 4984: An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
- 4985: The state of a transaction has changed.
- 4985: The state of a transaction has changed.
- 4985: The state of a transaction has changed.
- 4985: The state of a transaction has changed.
- 5024: The Windows Firewall Service has started successfully.
- 5025: The Windows Firewall Service has been stopped.
- 5027: The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.
- 5028: The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.
- 5029: The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.
- 5030: The Windows Firewall Service failed to start.
- 5031: The Windows Firewall Service blocked an application from accepting incoming connections on the network.
- 5032: Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.
- 5033: The Windows Firewall Driver has started successfully.
- 5034: The Windows Firewall Driver was stopped.
- 5035: The Windows Firewall Driver failed to start.
- 5037: The Windows Firewall Driver detected critical runtime error. Terminating.
- 5038: Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.
- 5039: A registry key was virtualized.
- 5040: A change has been made to IPsec settings. An Authentication Set was added.
- 5041: A change has been made to IPsec settings. An Authentication Set was modified.
- 5042: A change has been made to IPsec settings. An Authentication Set was deleted.
- 5043: A change has been made to IPsec settings. A Connection Security Rule was added.
- 5044: A change has been made to IPsec settings. A Connection Security Rule was modified.
- 5045: A change has been made to IPsec settings. A Connection Security Rule was deleted.
- 5046: A change has been made to IPsec settings. A Crypto Set was added.
- 5047: A change has been made to IPsec settings. A Crypto Set was modified.
- 5048: A change has been made to IPsec settings. A Crypto Set was deleted.
- 5049: An IPsec Security Association was deleted.
- 5051: A file was virtualized.
- 5056: A cryptographic self-test was performed.
- 5057: A cryptographic primitive operation failed.
- 5058: Key file operation.
- 5059: Key migration operation.
- 5060: Verification operation failed.
- 5061: Cryptographic operation.
- 5062: A kernel-mode cryptographic self-test was performed.
- 5063: A cryptographic provider operation was attempted.
- 5064: A cryptographic context operation was attempted.
- 5065: A cryptographic context modification was attempted.
- 5066: A cryptographic function operation was attempted.
- 5067: A cryptographic function modification was attempted.
- 5068: A cryptographic function provider operation was attempted.
- 5069: A cryptographic function property operation was attempted.
- 5070: A cryptographic function property modification was attempted.
- 5136: A directory service object was modified.
- 5137: A directory service object was created.
- 5138: A directory service object was undeleted.
- 5139: A directory service object was moved.
- 5140: A network share object was accessed.
- 5141: A directory service object was deleted.
- 5142: A network share object was added.
- 5143: A network share object was modified.
- 5144: A network share object was deleted.
- 5145: A network share object was checked to see whether client can be granted desired access.
- 5148: The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.
- 5149: The DoS attack has subsided and normal processing is being resumed.
- 5150: The Windows Filtering Platform blocked a packet.
- 5151: A more restrictive Windows Filtering Platform filter has blocked a packet.
- 5152: The Windows Filtering Platform blocked a packet.
- 5153: A more restrictive Windows Filtering Platform filter has blocked a packet.
- 5154: The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.
- 5155: The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.
- 5156: The Windows Filtering Platform has permitted a connection.
- 5157: The Windows Filtering Platform has blocked a connection.
- 5158: The Windows Filtering Platform has permitted a bind to a local port.
- 5159: The Windows Filtering Platform has blocked a bind to a local port.
- 5168: SPN check for SMB/SMB2 failed.
- 5376: Credential Manager credentials were backed up.
- 5377: Credential Manager credentials were restored from a backup.
- 5378: The requested credentials delegation was disallowed by policy.
- 5440: The following callout was present when the Windows Filtering Platform Base Filtering Engine started.
- 5441: The following filter was present when the Windows Filtering Platform Base Filtering Engine started.
- 5442: The following provider was present when the Windows Filtering Platform Base Filtering Engine started.
- 5443: The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.
- 5444: The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started.
- 5446: A Windows Filtering Platform callout has been changed.
- 5447: A Windows Filtering Platform filter has been changed.
- 5448: A Windows Filtering Platform provider has been changed.
- 5449: A Windows Filtering Platform provider context has been changed.
- 5450: A Windows Filtering Platform sub-layer has been changed.
- 5451: An IPsec Quick Mode security association was established.
- 5452: An IPsec Quick Mode security association ended.
- 5453: An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.
- 5456: PAStore Engine applied Active Directory storage IPsec policy on the computer.
- 5457: PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.
- 5458: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.
- 5459: PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.
- 5460: PAStore Engine applied local registry storage IPsec policy on the computer.
- 5461: PAStore Engine failed to apply local registry storage IPsec policy on the computer.
- 5462: PAStore Engine failed to apply some rules of the active IPsec policy on the computer. Use the IP Security Monitor snap-in to diagnose the problem.
- 5463: PAStore Engine polled for changes to the active IPsec policy and detected no changes.
- 5464: PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services.
- 5465: PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully.
- 5466: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead. Any changes made to the Active Directory IPsec policy since the last poll could not be applied.
- 5467: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy. The cached copy of the Active Directory IPsec policy is no longer being used.
- 5468: PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes. The cached copy of the Active Directory IPsec policy is no longer being used.
- 5471: PAStore Engine loaded local storage IPsec policy on the computer.
- 5472: PAStore Engine failed to load local storage IPsec policy on the computer.
- 5473: PAStore Engine loaded directory storage IPsec policy on the computer.
- 5474: PAStore Engine failed to load directory storage IPsec policy on the computer.
- 5477: PAStore Engine failed to add quick mode filter.
- 5478: IPsec Services has started successfully.
- 5479: IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5480: IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be started.
- 5484: IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
- 5485: IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
- 5632: A request was made to authenticate to a wireless network.
- 5633: A request was made to authenticate to a wired network.
- 5712: A Remote Procedure Call (RPC) was attempted.
- 5888: An object in the COM+ Catalog was modified.
- 5889: An object was deleted from the COM+ Catalog.
- 5890: An object was added to the COM+ Catalog.
- 6144: Security policy in the group policy objects has been applied successfully.
- 6145: One or more errors occurred while processing security policy in the group policy objects.
- 6272: Network Policy Server granted access to a user.
- 6273: Network Policy Server denied access to a user.
- 6274: Network Policy Server discarded the request for a user.
- 6275: Network Policy Server discarded the accounting request for a user.
- 6276: Network Policy Server quarantined a user.
- 6277: Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.
- 6278: Network Policy Server granted full access to a user because the host met the defined health policy.
- 6279: Network Policy Server locked the user account due to repeated failed authentication attempts.
- 6280: Network Policy Server unlocked the user account.
- 6281: Code Integrity determined that the page hashes of an image file are not valid. The file could be improperly signed without page hashes or corrupt due to unauthorized modification. The invalid hashes could indicate a potential disk device error.
- 6400: BranchCache: Received an incorrectly formatted response while discovering availability of content.
- 6401: BranchCache: Received invalid data from a peer. Data discarded.
- 6402: BranchCache: The message to the hosted cache offering it data is incorrectly formatted.
- 6403: BranchCache: The hosted cache sent an incorrectly formatted response to the client.
- 6404: BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.
- 6405: BranchCache: %2 instance(s) of event id %1 occurred.
- 6406: %1 registered to Windows Firewall to control filtering for the following: %2
- 6407: N/A
- 6408: Registered product %1 failed and Windows Firewall is now controlling the filtering for %2
- 6409: BranchCache: A service connection point object could not be parsed.
- 6410: Code integrity determined that a file does not meet the security requirements to load into a process.
- 6416: A new external device was recognized by the System
- 6419: A request was made to disable a device
- 6420: A device was disabled.
- 6421: A request was made to enable a device.
- 6422: A device was enabled.
- 6423: The installation of this device is forbidden by system policy.
- 6424: The installation of this device was allowed, after having previously been forbidden by policy.

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
