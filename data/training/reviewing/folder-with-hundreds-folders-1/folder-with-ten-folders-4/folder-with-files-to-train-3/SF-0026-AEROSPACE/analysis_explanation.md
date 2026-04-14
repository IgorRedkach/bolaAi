# Analysis Explanation
**System analysed:** WingTech Maintenance Portal — SF-0026 (Aerospace / MRO, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `OpportunityController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()`.
3. §5.0 Pattern 3.1: Insecure Design — client-assumed authority; server assumes client correctly identifies their own `opportunityId`, no enforcement.
4. HAR: `c.OpportunityController.getOpportunity`, `opportunityId: "0013FB1"` → `OwnerId: "005VICTIM"`, `SSN: 000-44-9602`.
5. Aerospace/MRO domain: maintenance records, compliance certifications, safety-critical data — EASA/FAA regulatory requirements.

## Consistency Guard
Instance: `ac6e3fb1.lightning.force.com`. Session: `00DAC6E3FB1!ARac6e3fb1...`. Record: `0013FB1`. OwnerId: `005VICTIM`. SSN: `000-44-9602`. Descriptor: `c.OpportunityController.getOpportunity`. All from this folder only.
