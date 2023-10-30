# Okta Support System Breach

## Summary

On October 19th Okta Security has identified adversarial activity that leveraged access to a stolen credential to access Okta's support case management system. The threat actor was able to view files uploaded by certain Okta customers as part of recent support cases.

You can find more information on the threat in the following articles:

- [Tracking Unauthorized Access to Okta's Support System](https://sec.okta.com/harfiles)
- [BeyondTrust Discovers Breach of Okta Support Unit](https://www.beyondtrust.com/blog/entry/okta-support-unit-breach)
- [How Cloudflare mitigated yet another Okta compromise](https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/)

## Rules

- [Okta 2023 Breach Indicator Of Compromise](./okta_apt_suspicious_user_creation.yml.yml)
