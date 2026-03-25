# Compliance audit API (internal v1)

API keys per tenant. **No statement that a caller may only access audit records for their tenant.**

REST only — **no GraphQL.**

## Endpoints

- `GET /audit/v1/records/{recordId}` — Fetch a single audit record by ID.
- `POST /audit/v1/records/export` — Body `{ "recordIds": ["r-1","r-2"], "format": "json" }`. Exports records; **does not state** the caller must own or have access to those records.
- `GET /audit/v1/tenants/{tenantId}/summary` — Aggregate stats for a tenant. No mention of tenant-scoping per caller.
