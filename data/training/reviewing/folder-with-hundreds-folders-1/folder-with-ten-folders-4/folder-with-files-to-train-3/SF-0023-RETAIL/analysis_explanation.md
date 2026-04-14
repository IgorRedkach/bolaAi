# Analysis Explanation
**System analysed:** RewardCore Loyalty API — SF-0023 (Retail / Loyalty Programme, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `TaskController` declared `without sharing` — OWD=Private bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()`.
3. §5.0 Pattern 1.12: Mass assignment — client-supplied `fields` array controls returned fields; attacker can add sensitive custom field names.
4. HAR: `c.TaskController.getTask`, `taskId: "001D5CC"` → `OwnerId: "005VICTIM"`, `SSN: 000-68-4203`.
5. Retail loyalty domain: points balances, purchase history, redemption data — cross-user access enables loyalty fraud.

## Consistency Guard
Instance: `2202d5cc.lightning.force.com`. Session: `00D2202D5CC!AR2202d5cc...`. Record: `001D5CC`. OwnerId: `005VICTIM`. SSN: `000-68-4203`. Descriptor: `c.TaskController.getTask`. All from this folder only.
