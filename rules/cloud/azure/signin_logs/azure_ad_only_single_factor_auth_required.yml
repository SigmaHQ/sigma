title: Azure AD Only Single Factor Authentication Required
id: 28eea407-28d7-4e42-b0be-575d5ba60b2c
status: test
description: Detect when users are authenticating without MFA being required.
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-user-accounts
author: MikeDuddington, '@dudders1'
date: 2022/07/27
tags:
    - attack.initial_access
    - attack.credential_access
    - attack.t1078.004
    - attack.t1556.006
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        AuthenticationRequirement: 'singleFactorAuthentication'
    condition: selection
falsepositives:
    - If this was approved by System Administrator.
level: low
