# Analysis Explanation
**System analysed:** VaultGuard IAM API — GQL-0094 (Cloud IAM)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.7 (nested resources without parent authorization). IAM child resources (role bindings, policies) accessible via `getResourceWithChildren` without re-validation.
2. HAR: `updateResource(id: "R-2094", input: {status: "approved", ownerId: "attacker-39548edb"})` from `tenant-3954`. Response `tenant-8edb`: `CONFIDENTIAL-39548edb`. `x-request-id: req-39548edb`.
3. IAM domain: unauthorized write to identity resource is privilege escalation — highest impact category.

## Consistency Guard
Tenant IDs: `tenant-3954`, `tenant-8edb`. Resource: `R-2094`. Attacker ownerId: `attacker-39548edb`. Leaked: `CONFIDENTIAL-39548edb`. Request: `req-39548edb`. All from this folder only.
