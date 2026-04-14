# Analysis Explanation
**System analysed:** ReactorCore Safety API — GQL-0240 (Nuclear / Safety Systems)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-240: `getResource` resolver lacks `tenantId` ownership check.
2. §5.0 Pattern 10.1: Single-User — ID swap in own request; attacker uses their own valid request structure but substitutes the `resourceId` with a victim's ID.
3. HAR: `tenant-1fd1` queries `getResource(id: "R-2240")` → `tenant-55d6` nuclear safety data: `CONFIDENTIAL-1fd155d6`, `req-1fd155d6`.
4. Nuclear/Safety domain: reactor parameters, safety system configs, maintenance records — highest criticality; IAEA and NIS2 reporting obligations.

## Consistency Guard
Attacker: `tenant-1fd1`. Victim: `tenant-55d6`. Resource: `R-2240`. Sensitive: `CONFIDENTIAL-1fd155d6`. ownerId: `other-user-1fd155d6`. Request: `req-1fd155d6`. All from this folder only.
