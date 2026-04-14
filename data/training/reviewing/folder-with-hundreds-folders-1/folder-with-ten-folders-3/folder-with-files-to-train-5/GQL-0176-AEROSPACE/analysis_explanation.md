# Analysis Explanation
**System analysed:** WingTech Maintenance Portal — GQL-0176 (Aerospace / Aviation Maintenance)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-176: `getResource` / `bulkResourceLookup` resolver fetches by `resourceId` without `tenantId` ownership check.
2. §5.0 Pattern 10.5: Draft/non-published resource access — bulk lookup returns draft records belonging to other tenants.
3. HAR: `tenant-0c7a` queries `bulkResourceLookup(ids: ["R-2176", "R-1176", "R-3176"])` → response includes `tenant-5893` draft record: `CONFIDENTIAL-0c7a5893`, `req-0c7a5893`.
4. Aerospace domain: draft maintenance records contain safety-critical repair data; cross-tenant exposure violates airworthiness regulations.

## Consistency Guard
Attacker: `tenant-0c7a`. Victim: `tenant-5893`. Resource: `R-2176`. Sensitive: `CONFIDENTIAL-0c7a5893`. ownerId: `other-user-0c7a5893`. Request: `req-0c7a5893`. All from this folder only.
