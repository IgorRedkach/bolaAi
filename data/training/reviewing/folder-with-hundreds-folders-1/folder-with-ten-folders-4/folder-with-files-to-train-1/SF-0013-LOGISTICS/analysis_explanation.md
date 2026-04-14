# Analysis Explanation
**System analysed:** FreightLens Tracking API — SF-0013 (Logistics / Supply Chain, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `OpportunityController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: `WHERE Id = :opportunityId` — no `AND OwnerId = :UserInfo.getUserId()` ownership check.
3. §5.0 Pattern 9.2: SOQL and Salesforce record-level access bypass via Aura controller.
4. HAR: `c.OpportunityController.getOpportunity` with `opportunityId: "00161E8"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-94-7793"`.
5. Logistics domain: shipment tracking, customer billing data, supply chain contracts — PII/SSN exposure at scale.
6. `aura.token: "undefined"` — Aura session token not validated server-side.

## Consistency Guard
Instance: `81c761e8.lightning.force.com`. Session: `00D81C761E8!`. Record: `00161E8`. OwnerId: `005VICTIM`. SSN: `000-94-7793`. Descriptor: `c.OpportunityController.getOpportunity`. All from this folder only.
