# Security Analysis Report
**System:** TeleCare Consultation API (Telemedicine / Remote Care) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0036 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.5 | Multi-tenant cross-user access — `CaseController.getCaseDetails` without ownership check exposes cross-user telemedicine case records |

---

## Finding 1 — Cross-User Telemedicine Case Access via Aura Controller (CRITICAL)

### Summary
The `CaseController` Apex class on TeleCare Consultation API (`5b7d2030.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Case records. Per §5.0 Pattern 1.5, the `getCaseDetails` action allows multi-tenant cross-user access: with no ownership validation, any session holder can access another user's telemedicine consultation case by substituting `caseId: "0012030"`. Case records contain patient consultation notes, diagnoses, and PHI.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://5b7d2030.lightning.force.com/aura`

### Evidence from HAR
**Request:** `caseId: 0012030` | **Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-43-4644`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class | OWD bypassed |
| §5.0 Pattern 1.5 | Multi-tenant BOLA | Classification | |
| HAR descriptor | `c.CaseController.getCaseDetails` | Entry point | |
| HAR params | `caseId` | `0012030` | Victim patient case |
| HAR response | `SensitiveData__c` | `SSN: 000-43-4644` | Patient PHI |

### Steps to Reproduce
```bash
curl -s -X POST "https://5b7d2030.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D5B7D2030!AR5b7d2030..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0012030","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class CaseController {`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side field allowlist; validate `aura.token`.
4. HIPAA: telemedicine case data is PHI — unauthorized access is a reportable breach; mandatory audit logging required.
