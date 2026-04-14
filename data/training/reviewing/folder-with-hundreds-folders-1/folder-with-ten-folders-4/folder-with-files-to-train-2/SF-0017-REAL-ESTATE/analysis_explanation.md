# Analysis Explanation
**System analysed:** EstateFlow Property API — SF-0017 (Real Estate / PropTech, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `LeadController` declared `without sharing` — OWD=Private for Lead bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` ownership check.
3. §5.0 Pattern 2.1: BAC — functional pivot; attacker pivots from their own lead-viewing function to accessing other agents' lead records using the same action.
4. HAR: `c.LeadController.getLeadData` with `leadId: "0011F52"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-88-1280"`.
5. Real estate/PropTech domain: buyer/seller PII, financial qualification data, agent commissions — cross-user access exposes regulated PII and competitive intelligence.
6. `aura.token: "undefined"` — no server-side Aura validation.

## Consistency Guard
Instance: `220b1f52.lightning.force.com`. Session: `00D220B1F52!AR220b1f52...`. Record: `0011F52`. OwnerId: `005VICTIM`. SSN: `000-88-1280`. Descriptor: `c.LeadController.getLeadData`. All from this folder only.
