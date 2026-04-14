# Analysis Explanation
**System analysed:** TaskFlow Collaboration API — GQL-0110 (SaaS / Project Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-110: `getProject` fetches by `projectId` only, enabling Pattern 10.5 (draft/non-published resource access).
2. HAR: `tenant-e31e` mutates `P-2110` with `ownerId: "attacker-e31e20bf"` → `tenant-20bf` data: `CONFIDENTIAL-e31e20bf`, `req-e31e20bf`.
3. SaaS: unpublished project roadmap — confidential business data.

## Consistency Guard
Attacker: `tenant-e31e`. Victim: `tenant-20bf`. Resource: `P-2110`. Sensitive: `CONFIDENTIAL-e31e20bf`. Input ownerId: `attacker-e31e20bf`. Request: `req-e31e20bf`. All from this folder only.
