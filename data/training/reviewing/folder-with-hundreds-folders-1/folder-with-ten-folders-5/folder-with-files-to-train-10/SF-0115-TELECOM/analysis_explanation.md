# Analysis Explanation
**Folder:** SF-0115-TELECOM | **Context source:** This folder's context.txt only.
- System: SpectreNet Policy Control, Telecom/5G Core/Policy Control, OWD: Private on Account
- Host: `e8839b8f.lightning.force.com`, token: `00DE8839B8F!ARe8839b8f...`
- Descriptor (HAR): `c.AccountController.getAccounts`, `accountId: "0019B8F"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getAccountDetails` but Aura descriptor in §6.0 is `getAccounts`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-70-7571`
- Pattern 2.1: Functional pivot — attacker uses `getAccounts` to read telecom policy Account records they don't own
**Consistency Guard:** All values from this folder's context.txt only.
