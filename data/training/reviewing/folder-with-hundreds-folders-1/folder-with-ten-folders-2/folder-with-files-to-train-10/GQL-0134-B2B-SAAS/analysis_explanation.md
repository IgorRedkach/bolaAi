# Analysis Explanation
**System analysed:** PipelinePro Sales API — GQL-0134 (B2B SaaS / CRM)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.2: `getProject` fetches by `projectId` without tenancy check — BOLA related linked resources.
2. HAR: `tenant-daf2` queries `P-2134` → `tenant-7e01` data: `CONFIDENTIAL-daf27e01`, `req-daf27e01`.
3. B2B SaaS/CRM: deal values, pipeline, customer intelligence — competitive sales data.

## Consistency Guard
Attacker: `tenant-daf2`. Victim: `tenant-7e01`. Resource: `P-2134`. Sensitive: `CONFIDENTIAL-daf27e01`. ownerId: `other-user-daf27e01`. Request: `req-daf27e01`. All from this folder only.
