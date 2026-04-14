# Analysis Explanation
**System analysed:** SkyPort Global Distribution — SF-0018 (Travel / GDS, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `OpportunityController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` check.
3. §5.0 Pattern 2.4: BAC — privilege escalation via parameter tampering; attacker substitutes `opportunityId` with victim's ID, gaining elevated access to records they do not own.
4. HAR: `c.OpportunityController.getOpportunity` with `opportunityId: "0018DBA"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-12-6889"`.
5. Travel/GDS domain: traveler PII, fare agreements, corporate travel accounts — PCI DSS and GDPR regulated.
6. `aura.token: "undefined"` — no server-side validation.

## Consistency Guard
Instance: `680b8dba.lightning.force.com`. Session: `00D680B8DBA!AR680b8dba...`. Record: `0018DBA`. OwnerId: `005VICTIM`. SSN: `000-12-6889`. Descriptor: `c.OpportunityController.getOpportunity`. All from this folder only.
