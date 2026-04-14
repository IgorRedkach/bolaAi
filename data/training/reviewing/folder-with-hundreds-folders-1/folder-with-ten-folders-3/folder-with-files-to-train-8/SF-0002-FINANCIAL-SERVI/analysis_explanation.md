# Analysis Explanation
**System analysed:** NexaBank Open Finance API (Salesforce-Integrated) — SF-0002 (Financial Services / Retail Banking)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-002: `ContactController` declared `without sharing` — Salesforce sharing rules not enforced.
2. §4.0 RISK-SF-003: SOQL WHERE clause missing `AND OwnerId = UserInfo.getUserId()` — no ownership check.
3. §5.0 Pattern 1.12: BOLA — mass assignment via object fields; client-supplied `fields` list includes privileged Salesforce fields.
4. HAR: attacker submits `c.ContactController.updateContact` with `contactId: "001EFE9"`, `fields: [...OwnerId, InternalNotes__c, SensitiveData__c]` → victim contact: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-71-5059"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Financial Services domain: customer SSNs, internal banking notes — PCI-DSS, GLBA, PSD2 violation.

## Consistency Guard
Attacker action: `c.ContactController.updateContact`. Victim record: `001EFE9`. Victim owner: `005VICTIM`. PII: `SSN: 000-71-5059`. Internal notes: `CONFIDENTIAL: internal review notes`. aura.token: `undefined`. All from this folder only.
