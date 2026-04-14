# Analysis Explanation
**System analysed:** TaskFlow Collaboration API — GQL-0210 (SaaS / Collaboration Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-210: `getProject` resolver fetches by `projectId` only, no `tenantId` ownership check.
2. §5.0 Pattern 3.1: Insecure Design — client-assumed authority; `ownerId` accepted as client-supplied authority claim.
3. HAR: `tenant-c34f` submits `updateProject(id: "P-2210", input: {ownerId: "attacker-c34fb8f9"})` → `tenant-b8f9` project: `CONFIDENTIAL-c34fb8f9`, `req-c34fb8f9`.
4. SaaS Collaboration domain: project roadmaps, team comms, business logic — IP theft and competitive intelligence breach.

## Consistency Guard
Attacker: `tenant-c34f`. Victim: `tenant-b8f9`. Project: `P-2210`. Sensitive: `CONFIDENTIAL-c34fb8f9`. ownerId input: `attacker-c34fb8f9`. Request: `req-c34fb8f9`. All from this folder only.
