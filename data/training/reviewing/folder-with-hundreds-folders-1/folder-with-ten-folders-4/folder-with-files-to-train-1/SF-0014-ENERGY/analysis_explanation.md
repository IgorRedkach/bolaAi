# Analysis Explanation
**System analysed:** PowerGrid Customer Billing API — SF-0014 (Energy / Utilities / Smart Grid, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `OpportunityController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: `WHERE Id = :opportunityId` — no ownership predicate.
3. §5.0 Pattern 10.2: Single-user parameter escalation — attacker extends their own session scope by substituting a victim's `opportunityId`.
4. HAR: `c.OpportunityController.getOpportunity` with `opportunityId: "0014434"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-64-1670"`.
5. Energy/Smart Grid domain: customer billing, smart meter data, energy consumption — regulated PII, critical infrastructure data.
6. `aura.token: "undefined"` — server-side Aura session not validated, amplifying the attack surface.

## Consistency Guard
Instance: `a8464434.lightning.force.com`. Session: `00DA8464434!ARa8464434...`. Record: `0014434`. OwnerId: `005VICTIM`. SSN: `000-64-1670`. Descriptor: `c.OpportunityController.getOpportunity`. All from this folder only.
