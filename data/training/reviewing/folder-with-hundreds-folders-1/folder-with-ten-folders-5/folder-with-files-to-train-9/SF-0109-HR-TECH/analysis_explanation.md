# Analysis Explanation
**Folder:** SF-0109-HR-TECH | **Context source:** This folder's context.txt only.
- System: JobCore Candidate Portal (SF), HR Tech/Talent Acquisition, OWD: Private on Lead
- Host: `d5202e03.lightning.force.com`, token: `00DD5202E03!ARd5202e03...`
- Descriptor (HAR): `c.LeadController.getLeadData`, `leadId: "0012E03"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getLeadDetails` but Aura descriptor in §6.0 is `getLeadData`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-70-2419` (candidate HR/PII data)
- Pattern 2.4: Privilege escalation via parameter tampering (BAC) — attacker tampers with `leadId` to escalate access beyond authorized level; reads candidate Lead records at privilege level they do not hold; `without sharing` bypasses OWD=Private
- §8.0 RISK-SF-109/110: controller without `with sharing`; no ownership check; client-supplied `leadId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.
