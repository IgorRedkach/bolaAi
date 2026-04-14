# Analysis Explanation
**System analysed:** LexVault eDiscovery API — SF-0024 (Legal Tech / Document Management, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `EventController` declared `without sharing` — OWD=Private for Event bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()`.
3. §5.0 Pattern 2.1: BAC — functional pivot; `updateEvent` is a write action exploited for cross-user record read by substituting `eventId`.
4. HAR: `c.EventController.updateEvent`, `eventId: "00133D3"` → `OwnerId: "005VICTIM"`, `SSN: 000-67-5672`.
5. Legal tech domain: litigation timelines, case milestones, attorney-client privileged data — unauthorized access may be attorney-client privilege violation.

## Consistency Guard
Instance: `3f3233d3.lightning.force.com`. Session: `00D3F3233D3!AR3f3233d3...`. Record: `00133D3`. OwnerId: `005VICTIM`. SSN: `000-67-5672`. Descriptor: `c.EventController.updateEvent`. All from this folder only.
