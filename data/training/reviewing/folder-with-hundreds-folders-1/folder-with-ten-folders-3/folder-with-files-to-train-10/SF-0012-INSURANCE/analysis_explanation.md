# Analysis Explanation
**System analysed:** ClaimsFlow Underwriting API (Salesforce-Integrated) — SF-0012 (Insurance / Underwriting)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-012: `EventController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-013: SOQL WHERE clause missing ownership check.
3. §5.0 Pattern 3.1: Insecure Design — client-assumed authority; `eventId` trusted as authoritative claim without server validation.
4. HAR: attacker submits `c.EventController.updateEvent` with `eventId: "0015CC1"` → victim insurance event: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-86-8999"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Insurance domain: claims event records — insurance fraud enablement.

## Consistency Guard
Action: `c.EventController.updateEvent`. Victim record: `0015CC1`. Victim owner: `005VICTIM`. PII: `SSN: 000-86-8999`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
