# Analysis Explanation
**Folder:** SF-0088-RAILWAY | **Context source:** This folder's context.txt only.
- System: RailCore Operations API (SF), Railway/SCADA, OWD: Private on Case
- Host: `5b1a374a.lightning.force.com`, token: `00D5B1A374A!AR5b1a374a...`
- Descriptor: `c.CaseController.getCaseDetails`, `caseId: "001374A"` (CONSISTENT)
- Response: `OwnerId: 005VICTIM`, `SSN: 000-32-8617`
- Pattern 2.4: Privilege escalation via parameter tampering — attacker substitutes `caseId` to read victim SCADA railway Case records
**Consistency Guard:** All values from this folder's context.txt only.
