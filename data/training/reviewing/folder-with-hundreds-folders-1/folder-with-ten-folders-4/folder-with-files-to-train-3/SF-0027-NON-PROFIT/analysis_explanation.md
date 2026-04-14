# Analysis Explanation
**System analysed:** GrantFlow CRM API — SF-0027 (Non-Profit / Grant Management, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `TaskController` declared `without sharing` — OWD=Private for Task bypassed.
2. SOQL: `WHERE Id = :taskId` only — no ownership predicate — SOQL record-level access bypass.
3. §5.0 Pattern 9.2: Platform — SOQL record-level access bypass; Salesforce sharing rules not enforced due to `without sharing`.
4. HAR: `c.TaskController.getTask`, `taskId: "001F6D4"` → `OwnerId: "005VICTIM"`, `SSN: 000-21-9631`.
5. Non-profit/Grant domain: beneficiary PII, grant applications, donor records — regulated data exposure.

## Consistency Guard
Instance: `83c5f6d4.lightning.force.com`. Session: `00D83C5F6D4!AR83c5f6d4...`. Record: `001F6D4`. OwnerId: `005VICTIM`. SSN: `000-21-9631`. Descriptor: `c.TaskController.getTask`. All from this folder only.
