# Analysis Explanation
**System analysed:** TaskFlow Collaboration API (Salesforce-Integrated) — SF-0010 (SaaS / Collaboration Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-010: `CaseController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-011: SOQL missing ownership check.
3. §5.0 Pattern 2.1: BAC — functional pivot (horizontal) via `caseId` substitution.
4. HAR: attacker submits `c.CaseController.getCaseDetails` with `caseId: "001D4E8"` → victim case: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-41-9351"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

## Consistency Guard
Action: `c.CaseController.getCaseDetails`. Victim record: `001D4E8`. Victim owner: `005VICTIM`. PII: `SSN: 000-41-9351`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
