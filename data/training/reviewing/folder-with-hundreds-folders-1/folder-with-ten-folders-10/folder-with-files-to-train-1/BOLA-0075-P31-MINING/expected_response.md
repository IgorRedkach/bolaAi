## System

- System: OreTrack Fleet Management v2.3.0
- Domain: MINING / RESOURCE EXTRACTION
- Example ID: BOLA-0075
- Risk ID: RISK-31-075

## Findings

### 1. Pattern 3.1 — Client-Assumed Authority on `/api/v1/objects/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-A4F3`. Request: `GET /api/v1/objects/OBJ-2075`. Response: HTTP 200 OK with `"tenantId": "ORG-A3EC"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-A3EC"`.

**Pattern 3.1 (Insecure Design — Client-Assumed Authority)**: the API design assumes that an authenticated client will only supply `object_id` values they are authorized to access. There is no server-side validation to enforce this assumption. The client is effectively "assumed" to have authority over any object ID they present. Section 4.0 confirms: the backend queries by `object_id` only. Section 3.0: "Application code does NOT use tenant_id in authorization checks."

**Mining/Fleet IoT impact**: `objects` represent mining fleet assets — vehicles, drilling units, or IoT sensor clusters. The `sensitive_data` field contains operational fleet intelligence. Write access (PATCH) via client-assumed authority enables a mining company to issue unauthorized status changes to another operator's fleet equipment.

### 2. Client-Assumed Write Authority via PATCH (Pattern 3.1 Extension)

Section 4.0: "GET/PATCH/DELETE `/api/v1/objects/:id`" — all verbs share the same unguarded handler. Client-assumed authority over read extends to client-assumed authority over write and delete — the design never validates authority at any operation.

## Evidence

- **HAR**: `GET /api/v1/objects/OBJ-2075` with `ORG-A4F3` JWT → HTTP 200 → `tenantId: ORG-A3EC` with `sensitiveData`.
- **Section 4.0 (RISK-31-075)**: Pattern 3.1 in `/api/v1/objects` — GET/PATCH/DELETE lack tenant/owner check.
- **Section 3.0**: Database schema comment: no `tenant_id` in authorization checks.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/objects/OBJ-1075" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A4F3>" \
  -H "X-Tenant-ID: ORG-A4F3"
```

Expected: `tenantId: "ORG-A4F3"`.

**Step 2 — Client-assumed authority: read cross-tenant fleet object (primary HAR attack):**

```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/objects/OBJ-2075" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A4F3>" \
  -H "X-Tenant-ID: ORG-A4F3"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-A3EC"` and `sensitiveData`.

**Step 3 — Client-assumed write authority: tamper with competitor's fleet object:**

```bash
curl -s -X PATCH "https://api.oretrack-fleet-.example.com/api/v1/objects/OBJ-2075" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A4F3>" \
  -H "X-Tenant-ID: ORG-A4F3" \
  -H "Content-Type: application/json" \
  -d '{"status": "suspended", "sensitive_data": "attacker_injected_command"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — competitor's mining fleet object status changed, potentially affecting IoT equipment operation.

**Step 4 — Client-assumed delete authority:**

```bash
curl -s -X DELETE "https://api.oretrack-fleet-.example.com/api/v1/objects/OBJ-2075" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A4F3>" \
  -H "X-Tenant-ID: ORG-A4F3"
```

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-31-075, unblock DB migration #DB-175).
- **Redesign authorization at the design level**: the insecure design flaw is that authority is assumed rather than verified — authorization must be a first-class design requirement for every handler.
- **Regression test**: Tenant A token requests Tenant B `object_id` via GET, PATCH, DELETE — assert HTTP 403/404.
