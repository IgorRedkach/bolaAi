# Analysis Explanation
**Folder:** SF-0073-RETAIL | **Context source:** This folder's context.txt only.
- System: RewardCore Loyalty API, Retail/Loyalty Platform, OWD: Private on Account
- Host: `b84f3016.lightning.force.com`, token: `00DB84F3016!ARb84f3016...`
- Descriptor (HAR): `c.AccountController.getAccounts`, `accountId: "0013016"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getAccountDetails` but Aura descriptor in §6.0 is `getAccounts`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-17-7717`
- Pattern 2.1: Functional pivot — `getAccounts` used to read loyalty Account records the attacker doesn't own
**Consistency Guard:** All values from this folder's context.txt only.
