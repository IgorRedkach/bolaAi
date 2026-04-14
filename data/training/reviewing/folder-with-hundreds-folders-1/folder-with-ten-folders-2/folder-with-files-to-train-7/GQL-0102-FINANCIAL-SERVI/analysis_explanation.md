# Analysis Explanation
**System analysed:** NexaBank Open Finance API — GQL-0102 (Financial Services)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 4.2 (persistence poisoning via lifecycle actions). Cross-tenant mutation poisons account ownership.
2. HAR: `bulkAccountLookup(["A-2102","A-1102","A-3102"])` from `tenant-d335`. Response `getAccount` from `tenant-690b`: `CONFIDENTIAL-d335690b`. `x-request-id: req-d335690b`.
3. Domain: `Account`/`accountId`/`getAccount`/`bulkAccountLookup` — confirmed by HAR response body.
4. PSD2/PSD3: Open Finance account data exposure is regulatory violation.

## Consistency Guard
Tenant IDs: `tenant-d335`, `tenant-690b`. Accounts: `A-2102`, `A-1102`, `A-3102`. ownerId: `other-user-d335690b`. Leaked: `CONFIDENTIAL-d335690b`. Request: `req-d335690b`. All from this folder only.
