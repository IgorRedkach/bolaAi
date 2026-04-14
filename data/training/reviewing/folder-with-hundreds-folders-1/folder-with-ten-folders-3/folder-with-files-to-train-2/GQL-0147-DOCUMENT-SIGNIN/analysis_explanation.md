# Analysis Explanation
**System analysed:** SignFlow eSign Platform — GQL-0147 (Document Signing / eSign)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 5.1: `updateResource` accepts `ownerId` in input — authorization-bypass injection.
2. HAR: `tenant-f03a` mutates `R-2147` with `ownerId: "attacker-f03ae845"` → `tenant-e845` data: `CONFIDENTIAL-f03ae845`, `req-f03ae845`.
3. eSign: legally binding contracts — unauthorized approval of legal documents.

## Consistency Guard
Attacker: `tenant-f03a`. Victim: `tenant-e845`. Resource: `R-2147`. Sensitive: `CONFIDENTIAL-f03ae845`. ownerId input: `attacker-f03ae845`. Request: `req-f03ae845`. All from this folder only.
