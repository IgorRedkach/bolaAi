# Analysis Explanation
**System analysed:** FirstResponse CAD Integration (Salesforce-Integrated) — SF-0008 (Government / Emergency Services)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-008: `ContactController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-009: SOQL WHERE clause missing ownership check.
3. §5.0 Pattern 1.5: BOLA — multi-tenant cross-tenant access via Aura `contactId` substitution.
4. HAR: attacker submits `c.ContactController.updateContact` with `contactId: "001BD65"` → victim contact: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-40-9675"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Government domain: emergency services contact records — CJIS/privacy violation.

## Consistency Guard
Action: `c.ContactController.updateContact`. Victim record: `001BD65`. Victim owner: `005VICTIM`. PII: `SSN: 000-40-9675`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
