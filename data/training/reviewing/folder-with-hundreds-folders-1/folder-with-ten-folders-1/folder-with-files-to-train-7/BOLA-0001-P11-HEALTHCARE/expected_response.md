## System

- System: PatientCore EHR API v1.3.0
- Domain: HEALTHCARE / EHR PLATFORM
- Example ID: BOLA-0001
- Risk ID: RISK-11-001

## Findings

### 1. Destructive Cross-Tenant BOLA via DELETE — ID in Path Without Ownership Check (Pattern 1.1)

The `DELETE /api/v1/items/:id` endpoint accepts an `item_id` in the URL path. Section 4.0 documents: "The backend handler queries the database by ID only, without filtering by `owner_id` or `tenant_id`." Section 3.0 code comment confirms: "Application code does NOT use tenant_id in authorization checks."

The HAR shows a DELETE request — not a read — against `ITE-2001` which belongs to `ORG-5F77`. The attacker's JWT carries `X-Tenant-ID: ORG-10AD`. The server returns HTTP 200 with the deleted record's content, confirming the cross-tenant DELETE was accepted and executed. In a healthcare EHR platform, deleting a patient clinical record owned by another organization is a catastrophic data integrity violation.

**HAR evidence**: JWT `X-Tenant-ID: ORG-10AD`. Request: `DELETE /api/v1/items/ITE-2001`. Response: HTTP 200 OK with body `{"tenantId": "ORG-5F77", "ownerId": "other-user-10ad5f77", "sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-5F77"}` — the endpoint processed and confirmed deletion of a record belonging to `ORG-5F77`.

**HIPAA impact**: deleting another organization's clinical item record constitutes unauthorized destruction of PHI. This violates HIPAA Security Rule §164.312(c)(2) (integrity controls) and could trigger a breach notification requirement under §164.410.

## Evidence

- **Section 4.0**: GET/PATCH/DELETE handler queries by `item_id` only — no `owner_id` or `tenant_id` filter.
- **Section 3.0 schema comment**: "Application code does NOT use tenant_id in authorization checks."
- **RISK-11-001** (section 6.0): "Pattern 1.1 detected in `/api/v1/items` handler. The handler was written before the tenant isolation policy was established."
- **HAR trace**: `DELETE /api/v1/items/ITE-2001` with `ORG-10AD` JWT → 200 OK → response confirms `tenantId: ORG-5F77` deletion.

## Reproduction

**Step 1 — Authorize baseline:**

```bash
curl -s -X GET "https://api.patientcore-ehr.example.com/api/v1/items/ITE-1001" \
  -H "Authorization: Bearer <TOKEN_ORG-10AD>" \
  -H "X-Tenant-ID: ORG-10AD"
```

Expected: returns own item with `tenantId: "ORG-10AD"`.

**Step 2 — Cross-tenant DELETE (primary HAR attack):**

```bash
curl -s -X DELETE "https://api.patientcore-ehr.example.com/api/v1/items/ITE-2001" \
  -H "Authorization: Bearer <TOKEN_ORG-10AD>" \
  -H "X-Tenant-ID: ORG-10AD"
```

Expected secure outcome: HTTP 403 or 404 — item `ITE-2001` belongs to `ORG-5F77`, not the requester.  
Expected vulnerable outcome: HTTP 200 with response body confirming `tenantId: "ORG-5F77"` — cross-tenant deletion executed.

**Step 3 — Cross-tenant read and patch (same path, same missing check):**

```bash
curl -s -X GET "https://api.patientcore-ehr.example.com/api/v1/items/ITE-2001" \
  -H "Authorization: Bearer <TOKEN_ORG-10AD>"
```

```bash
curl -s -X PATCH "https://api.patientcore-ehr.example.com/api/v1/items/ITE-2001" \
  -H "Authorization: Bearer <TOKEN_ORG-10AD>" \
  -H "Content-Type: application/json" \
  -d '{"status": "corrupted"}'
```

Expected vulnerable outcome: both return HTTP 200 — all three HTTP methods on the same path share the same missing authorization check.

## Remediation

- **Add tenant and ownership filter to all `/api/v1/items/:id` handlers** (RISK-11-001): `WHERE item_id = $id AND tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` — return 404 if no match (avoids leaking object existence).
- **Enforce the fix on all HTTP methods**: GET, PATCH, and DELETE handlers must all apply the same ownership check.
- **Complete DB migration ticket #DB-101**: section 6.0 notes the remediation is blocked pending this ticket — this must be prioritized given the DELETE impact.
- **Use non-sequential item IDs**: `ITE-2001` sequential pattern enables enumeration.
