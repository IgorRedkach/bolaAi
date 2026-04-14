# Analysis Explanation
**System analysed:** PayBridge Transaction API — SF-0020 (Fintech / Payments Gateway, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `TaskController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` check.
3. §5.0 Pattern 9.2: SOQL record-level access bypass — SOQL query returns any Task record by ID without ownership enforcement.
4. HAR: `c.TaskController.getTask` with `taskId: "001F71F"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-10-1011"`.
5. Fintech/Payments domain: transaction tasks, compliance reviews, customer financial identity — PCI DSS scope; cross-user access is a reportable breach.
6. `aura.token: "undefined"` — no server-side session validation.

## Consistency Guard
Instance: `5a83f71f.lightning.force.com`. Session: `00D5A83F71F!AR5a83f71f...`. Record: `001F71F`. OwnerId: `005VICTIM`. SSN: `000-10-1011`. Descriptor: `c.TaskController.getTask`. All from this folder only.
