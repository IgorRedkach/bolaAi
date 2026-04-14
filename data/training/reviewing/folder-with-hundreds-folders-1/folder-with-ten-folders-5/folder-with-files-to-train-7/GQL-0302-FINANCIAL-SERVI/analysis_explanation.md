# Analysis Explanation
**Folder:** GQL-0302-FINANCIAL-SERVI | **Context source:** This folder's context.txt only.
- System: NexaBank Open Finance API (GraphQL), Financial Services/Retail Banking
- Host: `api.nexabank-open-financ.example.com`
- Attacker tenant: `tenant-8101`, victim tenant: `tenant-e6d5`
- HAR query: `getAccount(id: "A-2302")`, response key: `getAccount` — CONSISTENT, no naming conflict
- Response: `ownerId: "other-user-8101e6d5"`, `sensitiveField: "CONFIDENTIAL-8101e6d5"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `accountId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-8101e6d5` is a response header (not a request header)
- Pattern 5.2: Resolver/graph traversal injection — `getAccount` resolver does not verify fetched `tenantId` vs JWT `tenantId`; nested resolver chain lacks per-level re-validation enabling cross-tenant traversal
- §4.0 RISK-GQL-302 explicitly documents this gap: resolver fetches by `accountId` only
**Consistency Guard:** All values from this folder's context.txt only.
