# Analysis Explanation
**System analysed:** Horizon Social Graph API (Salesforce-Integrated) — SF-0011 (Social Media / Content Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-011: `OpportunityController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-012: SOQL missing ownership check.
3. §5.0 Pattern 2.4: BAC — privilege escalation via `opportunityId` parameter tampering.
4. HAR: attacker submits `c.OpportunityController.getOpportunity` with `opportunityId: "00124A8"` → victim opportunity: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-92-5799"`.

## Consistency Guard
Action: `c.OpportunityController.getOpportunity`. Victim record: `00124A8`. Victim owner: `005VICTIM`. PII: `SSN: 000-92-5799`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.
