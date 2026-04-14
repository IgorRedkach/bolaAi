# Analysis Explanation
**Example:** SF-0119-MEDIA — StreamCore VOD Platform
**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.2 (Single-User — Parameter escalation) describes a specific threat model: the attacker is a legitimate, authenticated user of the platform who extends their own session's scope by tampering with a parameter that controls record access. Unlike horizontal privilege escalation (Pattern 2.2, where the attacker acts as a peer user reading peer records), Pattern 10.2 focuses on a single user extending what their own session can see beyond its intended boundary. The attacker's session is valid — the attack is purely about ID substitution within their own request. `LeadController` running `without sharing` and lacking an ownership predicate enables this: the SOQL returns any `Lead` record by ID, regardless of OWD=Private.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0119.

- **System Name:** StreamCore VOD Platform (§1.0)
- **Domain:** Media / Content Delivery
- **Host:** `ecc6042a.lightning.force.com` (§6.0 HAR)
- **Session token:** `00DECC6042A!ARecc6042a...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.LeadController.getLeadData` (§6.0)
- **Apex class method (§4.0):** `LeadController.getLeadDetails`
- **Object type:** Lead (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `001042A` (§6.0 HAR params)
- **Victim SSN:** `000-47-9460` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `LeadController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getLeadDetails`; §5.0 and §6.0 HAR use `c.LeadController.getLeadData`. HAR Aura descriptor is authoritative.

## Domain Risk

Media / VOD platform Lead records may represent content partner leads, subscriber leads, or content licensing prospects — containing PII (SSN: `000-47-9460`), internal deal notes, and business-sensitive data. A VOD platform user (possibly a content partner) extending their session scope to access other parties' records could expose competitive lead intelligence or subscriber PII.

## What the Model Should Learn

- Pattern 10.2 differs from 2.2 (horizontal escalation) in threat model: 10.2 is a single user extending their own scope; 2.2 is one user acting as another peer.
- The key marker for Pattern 10.2 is that the attacker uses their own valid session but changes the ID parameter to one they should not be able to access.
- In Salesforce, `without sharing` + no SOQL ownership predicate is the enabling condition for both 10.2 and 2.x patterns — the same underlying root cause manifests across multiple pattern types.
- Severity for 10.2 is typically HIGH rather than CRITICAL because the attacker must have a valid account, unlike unauthenticated exploitation.
