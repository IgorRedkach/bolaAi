# Analysis Explanation
**System analysed:** StreamCore VOD Platform — GQL-0069 (Media / Streaming)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.3 (bulk or list endpoints — BOLA). Bulk/list endpoints lack tenantId enforcement.
2. §4.0 RISK-GQL-069: `getResource` fetches by ID only — no tenantId match.
3. HAR: `updateResource(id: "R-2069", input: {status: "approved", ownerId: "attacker-6c3e0051"})` from `tenant-6c3e`. Response `tenant-0051`: `CONFIDENTIAL-6c3e0051`. `x-request-id: req-6c3e0051`.
4. Mass assignment angle: `ownerId` is writable in input — attacker injects their ID to capture ownership.

## Consistency Guard
Tenant IDs: `tenant-6c3e`, `tenant-0051`. Resource: `R-2069`. Attacker ownerId: `attacker-6c3e0051`. Leaked: `CONFIDENTIAL-6c3e0051`. Request: `req-6c3e0051`. All from this folder only.
