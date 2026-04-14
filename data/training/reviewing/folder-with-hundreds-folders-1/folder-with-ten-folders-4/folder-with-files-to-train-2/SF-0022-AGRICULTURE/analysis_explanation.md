# Analysis Explanation
**System analysed:** HarvestIQ IoT Platform — SF-0022 (Agriculture / Precision Farming, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `EventController` declared `without sharing` — OWD=Private for Event bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` ownership check.
3. §5.0 Pattern 1.5: BOLA — multi-tenant/cross-user access; `updateEvent` is a write action, meaning attacker can not only read but also modify victim's IoT farming event records.
4. HAR: `c.EventController.updateEvent` with `eventId: "0019156"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-52-2911"`.
5. Agriculture/IoT domain: crop schedules, sensor telemetry, field configurations — proprietary precision farming IP; write access allows sabotage of irrigation/harvest operations.
6. `aura.token: "undefined"` — no server-side Aura validation.

## Consistency Guard
Instance: `61db9156.lightning.force.com`. Session: `00D61DB9156!AR61db9156...`. Record: `0019156`. OwnerId: `005VICTIM`. SSN: `000-52-2911`. Descriptor: `c.EventController.updateEvent`. All from this folder only.
