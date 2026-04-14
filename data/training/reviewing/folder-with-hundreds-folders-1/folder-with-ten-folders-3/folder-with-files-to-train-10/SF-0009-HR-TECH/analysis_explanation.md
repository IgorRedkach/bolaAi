# Analysis Explanation
**System analysed:** JobCore Candidate Portal (Salesforce-Integrated) — SF-0009 (HR Tech / Talent Acquisition)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-009: `CustomObjectController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-010: SOQL WHERE clause missing ownership check.
3. §5.0 Pattern 1.12: BOLA — mass assignment via client-supplied privileged `fields` list.
4. HAR: attacker submits `c.CustomObjectController.getRecord` with `recordId: "00151C1"`, `fields: [...OwnerId, SensitiveData__c]` → victim candidate: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-74-7444"`.
5. HR Tech domain: candidate custom records — GDPR and employment privacy violation.

## Consistency Guard
Action: `c.CustomObjectController.getRecord`. Victim record: `00151C1`. Victim owner: `005VICTIM`. PII: `SSN: 000-74-7444`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
