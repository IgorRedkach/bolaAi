# Analysis Explanation
**System analysed:** PayBridge Transaction API — GQL-0070 (FinTech / Payments)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.5 (multi-tenant/cross-tenant access). `listResources(tenantId:)` trusts client-supplied argument — classic cross-tenant data leak.
2. §4.0 RISK-GQL-070: `getResource` fetches by ID only — no tenantId match.
3. HAR: `getResource(id: "R-2070")` from `tenant-4015`. Response `tenant-378f`: `CONFIDENTIAL-4015378f`. `x-request-id: req-4015378f`.
4. Pattern 1.5 is explicit in §5.0: "trusts client-supplied `tenantId` instead of JWT" — both `getResource` and `listResources` vectors documented.

## Consistency Guard
Tenant IDs: `tenant-4015`, `tenant-378f`. Resource: `R-2070`. ownerId: `other-user-4015378f`. Leaked: `CONFIDENTIAL-4015378f`. Request: `req-4015378f`. All from this folder only.
