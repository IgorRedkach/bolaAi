# Analysis Explanation
**Folder:** GQL-0314-ENERGY | **Context source:** This folder's context.txt only.
- System: PowerGrid Customer Billing API (GraphQL), Energy/Utilities/Smart Grid
- Host: `api.powergrid-customer-b.example.com`
- Attacker tenant: `tenant-1f71`, victim tenant: `tenant-6060`
- HAR query: `getMeter(id: "M-2314")`, response key: `getMeter` — CONSISTENT, no naming conflict
- Response: `ownerId: "other-user-1f716060"`, `sensitiveField: "CONFIDENTIAL-1f716060"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `meterId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-1f716060` is a response header (not a request header)
- Pattern 1.7: Nested resources without parent authorization (BOLA) — `getMeter` resolver lacks `tenantId` cross-check; nested `readings` child resources are accessible without re-validating parent authorization; parent-level authorization gap propagates to all child resources
- §4.0 RISK-GQL-314: `getMeter` fetches by `meterId` only; `bulkMeterLookup` lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
