# Analysis Explanation

**System analysed:** NexaBank Open Finance API — GQL-0052 (Financial Services / Retail Banking)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 1.9 (batch/bulk lookup). "`bulkAccountLookup` accepts a list of IDs without per-ID ownership checks. A single request can enumerate objects across all tenants."
2. **Read §3.0** — Domain-specific types: `Account`, `accountId`, `bulkAccountLookup`, `updateAccount`.
3. **Read §4.0** — RISK-GQL-052 + bulkAccountLookup no per-ID filter. Cache keyed by `accountId` only.
4. **Read HAR** — `updateAccount(id: "A-2052", input: {status: "approved", ownerId: "attacker-89e25fd4"})`. Response `tenant-5fd4`: `CONFIDENTIAL-89e25fd4`. `x-request-id: req-89e25fd4`.
5. **HAR is write, §5.0 describes bulk** — Both documented: HAR (write BOLA) as Finding 1, §5.0 `bulkAccountLookup` as Step 2.

## Consistency Guard
- Tenant IDs: `tenant-89e2`, `tenant-5fd4`. Account: `A-2052`. Injected ownerId: `attacker-89e25fd4`. Leaked: `CONFIDENTIAL-89e25fd4`, `other-user-89e25fd4`. Request ID: `req-89e25fd4`. All from this folder only.
