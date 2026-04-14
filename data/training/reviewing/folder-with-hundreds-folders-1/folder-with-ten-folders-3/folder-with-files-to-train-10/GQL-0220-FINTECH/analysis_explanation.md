# Analysis Explanation
**System analysed:** PayBridge Transaction API — GQL-0220 (FinTech / Payment Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-220: `getResource`/`bulkResourceLookup` resolver lacks `tenantId` check.
2. §5.0 Pattern 10.5: Single-User — draft/non-published resource access via bulk lookup cross-tenant.
3. HAR: `tenant-a29c` queries `bulkResourceLookup(ids: ["R-2220", "R-1220", "R-3220"])` → `tenant-c25b` draft transaction: `CONFIDENTIAL-a29cc25b`, `req-a29cc25b`.
4. FinTech domain: draft payment records, settlement data — financial fraud enablement.

## Consistency Guard
Attacker: `tenant-a29c`. Victim: `tenant-c25b`. Resource: `R-2220`. Sensitive: `CONFIDENTIAL-a29cc25b`. ownerId: `other-user-a29cc25b`. Request: `req-a29cc25b`. All from this folder only.
