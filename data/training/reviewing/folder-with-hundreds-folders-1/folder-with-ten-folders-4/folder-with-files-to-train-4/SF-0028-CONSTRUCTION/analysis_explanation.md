# Analysis Explanation
**System analysed:** BuildCore BIM Collaboration — SF-0028 (Construction / BIM Platform, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `OpportunityController` `without sharing` — OWD=Private bypassed.
2. No SOQL ownership check.
3. §5.0 Pattern 10.2: Session scope extension — `opportunityId: "00124B9"` substituted → `OwnerId: 005VICTIM`, `SSN: 000-99-3221`.
4. Construction/BIM: blueprints, contractor agreements, site configs — IP and compliance risk.

## Consistency Guard
Instance: `f71d24b9.lightning.force.com`. Session: `00DF71D24B9!ARf71d24b9...`. Record: `00124B9`. OwnerId: `005VICTIM`. SSN: `000-99-3221`. Descriptor: `c.OpportunityController.getOpportunity`. All from this folder only.
