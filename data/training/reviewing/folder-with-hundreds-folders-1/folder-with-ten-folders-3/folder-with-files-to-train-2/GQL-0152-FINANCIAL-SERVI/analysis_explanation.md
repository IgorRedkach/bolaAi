# Analysis Explanation
**System analysed:** NexaBank Open Finance API — GQL-0152 (Financial Services / Retail Banking)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.1: `updateAccount` ID swap — no ownership check.
2. HAR: `tenant-404b` mutates `A-2152` with `ownerId: "attacker-404b4b6d"` → `tenant-4b6d` account: `CONFIDENTIAL-404b4b6d`, `req-404b4b6d`.
3. Financial Services: account details, balances — PSD2/Open Finance regulatory risk.

## Consistency Guard
Attacker: `tenant-404b`. Victim: `tenant-4b6d`. Resource: `A-2152`. Sensitive: `CONFIDENTIAL-404b4b6d`. ownerId input: `attacker-404b4b6d`. Request: `req-404b4b6d`. All from this folder only.
