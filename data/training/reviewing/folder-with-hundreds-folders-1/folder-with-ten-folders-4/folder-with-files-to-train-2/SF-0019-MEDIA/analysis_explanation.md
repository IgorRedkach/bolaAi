# Analysis Explanation
**System analysed:** StreamCore VOD Platform — SF-0019 (Media / Content Delivery, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `AccountController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` check.
3. §5.0 Pattern 3.1: Insecure Design — client-assumed authority; server trusts client to supply only their own `accountId`, with no server-side enforcement.
4. HAR: `c.AccountController.getAccounts` with `accountId: "001D2DD"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-41-6960"`.
5. Media/VOD domain: subscriber PII, content licensing, viewing analytics, billing — GDPR/CCPA regulated.
6. `aura.token: "undefined"` — no server-side validation.

## Consistency Guard
Instance: `a992d2dd.lightning.force.com`. Session: `00DA992D2DD!ARa992d2dd...`. Record: `001D2DD`. OwnerId: `005VICTIM`. SSN: `000-41-6960`. Descriptor: `c.AccountController.getAccounts`. All from this folder only.
