# Analysis Explanation
**Folder:** GQL-0307-INDUSTRIAL-IOT | **Context source:** This folder's context.txt only.
- System: ManuControl Robotics Fleet (GraphQL), Industrial IoT/Manufacturing
- Host: `api.manucontrol-robotics.example.com`
- Attacker tenant: `tenant-8009`, victim tenant: `tenant-879e`
- HAR mutation: `bulkResourceLookup(ids: ["R-2307", "R-1307", "R-3307"])`, response key: `getResource` — **INCONSISTENCY**: HAR uses `bulkResourceLookup` mutation but response key is `getResource`. HAR operation is authoritative.
- Response: `ownerId: "other-user-8009879e"`, `sensitiveField: "CONFIDENTIAL-8009879e"`, `internalNotes: "Internal data exposed"` — cross-tenant industrial equipment data exposed in bulk
- Redis cache keyed by `resourceId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-8009879e` is a response header (not a request header)
- Pattern 10.2: Parameter escalation (own session scope extension) — single attacker token used to bulk-request multiple victim `resourceId` values; `bulkResourceLookup` lacks per-ID tenancy check; attacker extends their session scope to access cross-tenant manufacturing robot telemetry
- §4.0 RISK-GQL-307: `getResource` fetches by `resourceId` only; `bulkResourceLookup` lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
