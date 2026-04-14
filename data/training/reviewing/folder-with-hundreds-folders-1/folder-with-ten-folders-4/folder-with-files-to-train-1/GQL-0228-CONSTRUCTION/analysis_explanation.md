# Analysis Explanation
**System analysed:** BuildCore BIM Collaboration — GQL-0228 (Construction / BIM Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-228: `listResources` accepts arbitrary `tenantId` query parameter — not validated against JWT.
2. §5.0 Pattern 1.9: BOLA — bulk list endpoint enables cross-tenant enumeration.
3. HAR: `tenant-2a4c` calls `listResources(tenantId: "tenant-f465")` → returns `tenant-f465` BIM resources: `CONFIDENTIAL-2a4cf465`, `req-2a4cf465`.
4. Construction/BIM domain: building blueprints, structural plans, project schedules — competitor espionage and IP theft risk.
5. `listResources` schema accepts `tenantId: ID` as optional parameter — attacker simply provides victim's tenant ID.

## Consistency Guard
Attacker: `tenant-2a4c`. Victim: `tenant-f465`. Sensitive: `CONFIDENTIAL-2a4cf465`. ownerId: `other-user-2a4cf465`. Request: `req-2a4cf465`. All from this folder only.
