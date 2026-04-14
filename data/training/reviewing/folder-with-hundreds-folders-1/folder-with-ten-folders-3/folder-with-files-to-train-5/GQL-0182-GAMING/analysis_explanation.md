# Analysis Explanation
**System analysed:** RealmForge Game API — GQL-0182 (Gaming / Online Multiplayer)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-182: `getCharacter` resolver fetches by `characterId` only, no parent account `tenantId` ownership check.
2. §5.0 Pattern 1.7: BOLA — nested resource (character) accessible without parent authorization.
3. HAR: `tenant-228c` queries `getCharacter(id: "C-2182")` → `tenant-7c62` character record: `CONFIDENTIAL-228c7c62`, `req-228c7c62`.
4. Gaming domain: character inventory, progression, in-game economy — item theft and competitive exploitation.

## Consistency Guard
Attacker: `tenant-228c`. Victim: `tenant-7c62`. Character: `C-2182`. Sensitive: `CONFIDENTIAL-228c7c62`. ownerId: `other-user-228c7c62`. Request: `req-228c7c62`. All from this folder only.
