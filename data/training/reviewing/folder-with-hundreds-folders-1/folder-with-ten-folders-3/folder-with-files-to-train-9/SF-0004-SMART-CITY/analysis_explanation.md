# Analysis Explanation
**System analysed:** MetroPulse Traffic Orchestration (Salesforce-Integrated) — SF-0004 (Smart City / Traffic Orchestration)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-004: `EventController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-005: SOQL WHERE clause missing ownership check.
3. §5.0 Pattern 2.4: BAC — privilege escalation via `eventId` parameter tampering.
4. HAR: attacker submits `c.EventController.updateEvent` with `eventId: "001A296"` → victim event: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-87-4441"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Smart City domain: traffic event records — infrastructure manipulation risk.

## Consistency Guard
Action: `c.EventController.updateEvent`. Victim record: `001A296`. Victim owner: `005VICTIM`. PII: `SSN: 000-87-4441`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
