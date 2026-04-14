# Analysis Explanation
**System analysed:** NexaBank Open Finance API — GQL-0202 (Financial Services / Open Banking)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-202: `getAccount`/`listAccounts` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 1.5: BOLA — multi-tenant/cross-tenant access via injected `tenantId` filter.
3. HAR: `tenant-99f3` queries `listAccounts(tenantId: "tenant-4b01")` → `tenant-4b01` account records: `CONFIDENTIAL-99f34b01`, `req-99f34b01`.
4. Financial Services domain: account balances, transaction histories — PSD2 violation and fraud enablement.

## Consistency Guard
Attacker: `tenant-99f3`. Victim: `tenant-4b01`. Account: `A-2202`. Sensitive: `CONFIDENTIAL-99f34b01`. ownerId: `other-user-99f34b01`. Request: `req-99f34b01`. All from this folder only.
