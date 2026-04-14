# Analysis Explanation
**System analysed:** NeoBuild BAS Platform — GQL-0193 (Smart Home / Building Automation)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-193: `getResource` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 6.1: Misconfiguration — schema/relationship over-exposure; `ownerId` and `tenantId` exposed in mutation input type.
3. HAR: `tenant-1531` submits `updateResource(id: "R-2193", input: {ownerId: "attacker-15311211"})` → `tenant-1211` device data: `CONFIDENTIAL-15311211`, `req-15311211`.
4. Smart Home BAS domain: device configs, automation rules — physical access bypass and safety system interference.

## Consistency Guard
Attacker: `tenant-1531`. Victim: `tenant-1211`. Resource: `R-2193`. Sensitive: `CONFIDENTIAL-15311211`. ownerId input: `attacker-15311211`. Request: `req-15311211`. All from this folder only.
