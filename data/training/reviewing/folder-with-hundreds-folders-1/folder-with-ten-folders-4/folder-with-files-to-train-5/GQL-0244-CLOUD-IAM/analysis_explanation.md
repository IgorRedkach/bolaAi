# Analysis Explanation
**System analysed:** VaultGuard IAM API — GQL-0244 (Cloud IAM / Identity Provider)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-244: `getResource` lacks `tenantId` check.
2. §5.0 Pattern 1.2: BOLA — related/linked resources; IAM resources are linked to roles, policies, credentials — accessing one cross-tenant exposes the full linked tree.
3. HAR: `tenant-3c33` queries `getResource(id: "R-2244")` → `tenant-b5be` data: `CONFIDENTIAL-3c33b5be`, `req-3c33b5be`.
4. Cloud IAM domain: credentials, role policies, identity configurations — cross-tenant access enables cloud privilege escalation.

## Consistency Guard
Attacker: `tenant-3c33`. Victim: `tenant-b5be`. Resource: `R-2244`. Sensitive: `CONFIDENTIAL-3c33b5be`. ownerId: `other-user-3c33b5be`. Request: `req-3c33b5be`. All from this folder only.
