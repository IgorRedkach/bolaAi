# Analysis Explanation
**Folder:** GQL-0315-TELECOM | **Context source:** This folder's context.txt only.
- System: SpectreNet Policy Control (GraphQL), Telecom/5G Core
- Host: `api.spectrenet-policy-co.example.com`
- Attacker tenant: `tenant-7b66`, victim tenant: `tenant-309b`
- HAR mutation: `bulkResourceLookup(ids: ["R-2315", "R-1315", "R-3315"])`, response key: `getResource` — **INCONSISTENCY**: HAR uses `bulkResourceLookup` but response key is `getResource`. HAR operation is authoritative.
- Response: `ownerId: "other-user-7b66309b"`, `sensitiveField: "CONFIDENTIAL-7b66309b"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `resourceId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-7b66309b` is a response header (not a request header)
- Pattern 1.8: Predictable/sequential IDs (BOLA) — IDs follow pattern `R-XXXX` (sequential/incremental); attacker iterates adjacent IDs to enumerate cross-tenant 5G core policy records; `bulkResourceLookup` compounds this by accepting multiple IDs per request without per-ID tenancy check
- §4.0 RISK-GQL-315: `getResource` fetches by `resourceId` only; `bulkResourceLookup` lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
