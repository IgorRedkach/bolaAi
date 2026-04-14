# Analysis Explanation
**Folder:** SF-0108-GOVERNMENT | **Context source:** This folder's context.txt only.
- System: FirstResponse CAD Integration (SF), Government/Public Safety, OWD: Private on Lead
- Host: `96e67f99.lightning.force.com`, token: `00D96E67F99!AR96e67f99...`
- Descriptor (HAR): `c.LeadController.getLeadData`, `leadId: "0017F99"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getLeadDetails` but Aura descriptor in §6.0 is `getLeadData`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-93-4323` (public safety personnel PII)
- Pattern 2.1: Functional pivot (BAC) — attacker pivots to the Lead controller (originally designed for lead management) to read CAD-associated lead records that should not be accessible; `without sharing` bypasses OWD=Private
- §8.0 RISK-SF-108/109: controller without `with sharing`; no ownership check; client-supplied `leadId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.
