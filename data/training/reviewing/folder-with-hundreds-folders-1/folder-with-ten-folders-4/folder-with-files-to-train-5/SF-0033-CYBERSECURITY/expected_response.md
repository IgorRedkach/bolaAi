# Security Analysis Report
**System:** ThreatLens SOC Platform (Cybersecurity / SIEM) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0033 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design / Pattern 3.1 | Client-assumed authority — `TaskController.getTask` trusts client `taskId`, exposing cross-user SOC threat task records |

---

## Finding 1 — Client-Assumed Authority: Cross-User SIEM Task Record Access (CRITICAL)

### Summary
The `TaskController` Apex class on ThreatLens SOC Platform (`027089d1.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 3.1, the `getTask` Aura action is vulnerable to client-assumed authority: the design assumes the client will only query their own tasks. An attacker supplies `taskId: "00189D1"` to access another analyst's SOC threat investigation task record.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://027089d1.lightning.force.com/aura`

### Evidence from HAR
**Request:** `taskId: 00189D1` | **Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-57-6720`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class | OWD bypassed |
| §5.0 Pattern 3.1 | Client-assumed authority | Classification | No server enforcement |
| HAR descriptor | `c.TaskController.getTask` | Entry point | |
| HAR params | `taskId` | `00189D1` | Victim SOC task |
| HAR response | `SensitiveData__c` | `SSN: 000-57-6720` | Analyst PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://027089d1.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D027089D1!AR027089d1..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"00189D1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class TaskController {`
2. `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side field allowlist; validate `aura.token`.
4. SOC threat investigation tasks may contain sensitive incident IOC data — cross-user access enables intelligence leakage.
