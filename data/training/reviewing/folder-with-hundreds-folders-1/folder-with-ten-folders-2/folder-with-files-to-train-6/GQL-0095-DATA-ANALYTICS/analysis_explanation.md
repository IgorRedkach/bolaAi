# Analysis Explanation
**System analysed:** InsightGraph Analytics API — GQL-0095 (Data Analytics / BI)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.8 (predictable/sequential IDs — BOLA). IDs are numeric/sequential (R-2095, R-2094...); no tenantId guard enables enumeration.
2. HAR: `updateResource(id: "R-2095", input: {status: "approved", ownerId: "attacker-f455861b"})` from `tenant-f455`. Response `tenant-861b`: `CONFIDENTIAL-f455861b`. `x-request-id: req-f455861b`.
3. Write + sequential IDs = systematic data exfiltration + modification of proprietary analytics datasets.

## Consistency Guard
Tenant IDs: `tenant-f455`, `tenant-861b`. Resource: `R-2095`. Attacker ownerId: `attacker-f455861b`. Leaked: `CONFIDENTIAL-f455861b`. Request: `req-f455861b`. All from this folder only.
