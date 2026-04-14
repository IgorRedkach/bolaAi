# Analysis Explanation
**System analysed:** PipelinePro Sales API — GQL-0184 (B2B SaaS / Sales Intelligence)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-184: `getProject` resolver fetches by `projectId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.9: BOLA — batch/bulk lookup endpoints return cross-tenant project data.
3. HAR: `tenant-35b9` queries `getProject(id: "P-2184")` → `tenant-d66b` sales project: `CONFIDENTIAL-35b9d66b`, `req-35b9d66b`.
4. B2B SaaS domain: pipeline data, deal values, customer lists — competitive intelligence breach.

## Consistency Guard
Attacker: `tenant-35b9`. Victim: `tenant-d66b`. Project: `P-2184`. Sensitive: `CONFIDENTIAL-35b9d66b`. ownerId: `other-user-35b9d66b`. Request: `req-35b9d66b`. All from this folder only.
