# Analysis Explanation
**System analysed:** LearnPath Assessment Platform — SF-0016 (Education / EdTech LMS, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `TaskController` declared `without sharing` — OWD=Private for Task bypassed.
2. SOQL: `WHERE Id = :taskId` — no `AND OwnerId = :UserInfo.getUserId()`.
3. §5.0 Pattern 1.12: Mass assignment — client supplies `fields` array controlling which object fields are returned; attacker can enumerate all custom fields by adding them to the `fields` list.
4. §8.0 RISK-SF-016/017: Documented known gaps confirming both vulnerabilities.
5. HAR: `c.TaskController.getTask` with `taskId: "0013007"` + `fields: ["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-84-7983"`.
6. Education/LMS domain: student assessments, grades, FERPA-protected data — cross-user access has regulatory consequences.
7. `aura.token: "undefined"` — server-side Aura session not validated.

## Consistency Guard
Instance: `8c7d3007.lightning.force.com`. Session: `00D8C7D3007!AR8c7d3007...`. Record: `0013007`. OwnerId: `005VICTIM`. SSN: `000-84-7983`. Descriptor: `c.TaskController.getTask`. All from this folder only.
