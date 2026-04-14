# Analysis Explanation
**System analysed:** AeroOps Flight Management — SF-0037 (Aviation / Flight Ops, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `TaskController` `without sharing` — OWD=Private bypassed.
2. No SOQL ownership check.
3. §5.0 Pattern 1.12: Mass assignment — client-supplied `fields` array controls returned fields.
4. HAR: `c.TaskController.getTask`, `taskId: "001AB0B"`, `fields: [...sensitive]` → `OwnerId: 005VICTIM`, `SSN: 000-13-2632`.
5. Aviation domain: flight tasks, maintenance instructions, crew assignments — safety-critical EASA/FAA.

## Consistency Guard
Instance: `e24eab0b.lightning.force.com`. Session: `00DE24EAB0B!ARe24eab0b...`. Record: `001AB0B`. OwnerId: `005VICTIM`. SSN: `000-13-2632`. Descriptor: `c.TaskController.getTask`. All from this folder only.
