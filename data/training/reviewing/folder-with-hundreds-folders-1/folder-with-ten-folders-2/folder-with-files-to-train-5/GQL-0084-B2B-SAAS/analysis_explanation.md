# Analysis Explanation
**System analysed:** PipelinePro Sales API — GQL-0084 (B2B SaaS / Sales Pipeline)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 7.1 (operational PII/PHI leakage — logging failures). Successful cross-tenant mutation response is logged with sensitive data.
2. HAR: `updateProject(id: "P-2084", input: {status: "approved", ownerId: "attacker-2b57b8d4"})` from `tenant-2b57`. Response `getProject` from `tenant-b8d4`: `CONFIDENTIAL-2b57b8d4`. `x-request-id: req-2b57b8d4`.
3. Key observation: domain objects are `Project`/`projectId` with `updateProject`/`getProject` resolvers (not generic `Resource`) — confirmed by HAR response body (`getProject`).
4. Pattern 7.1 angle: logging failure is secondary harm — primary BOLA + logging means PII persists in log aggregation systems.

## Consistency Guard
Tenant IDs: `tenant-2b57`, `tenant-b8d4`. Project: `P-2084`. Attacker ownerId injected: `attacker-2b57b8d4`. Leaked: `CONFIDENTIAL-2b57b8d4`. Request: `req-2b57b8d4`. All from this folder only.
