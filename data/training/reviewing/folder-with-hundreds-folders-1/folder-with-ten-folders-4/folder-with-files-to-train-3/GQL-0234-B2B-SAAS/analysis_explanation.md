# Analysis Explanation
**System analysed:** PipelinePro Sales API — GQL-0234 (B2B SaaS / CRM)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-234: `updateProject` resolver fetches by `projectId` only — no `tenantId` ownership check.
2. §5.0 Pattern 4.2: Integrity — persistence poisoning via lifecycle action; attacker mutates victim's CRM pipeline state and attempts ownership hijack.
3. HAR: `tenant-c37d` issues `updateProject(id: "P-2234", input: {status: "approved", ownerId: "attacker-c37d0fc1"})` → `tenant-0fc1` project data: `CONFIDENTIAL-c37d0fc1`, `req-c37d0fc1`.
4. B2B SaaS/CRM domain: pipeline stages, deal approvals, ownership — corrupting lifecycle state enables deal hijacking and workflow fraud.

## Consistency Guard
Attacker: `tenant-c37d`. Victim: `tenant-0fc1`. Project: `P-2234`. Sensitive: `CONFIDENTIAL-c37d0fc1`. ownerId: `other-user-c37d0fc1`. Request: `req-c37d0fc1`. All from this folder only.
