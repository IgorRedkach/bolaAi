# Why “keep improving until done” often did not happen (analysis)

This document explains **root causes** for repeated user requests to **not stop early** and to **chain improvement loops automatically**, and how we hardened the process.

## 1. Model and task shape (intrinsic)

- **Completion bias:** Assistants are trained to produce a **satisfying closing summary** (“looks good,” “minor improvements possible,” “next steps for you”). That reads as **done** even when work remains.
- **Subjective stop rules:** Phrases like *“no further improvements you can name”* are **easy to satisfy** by naming fewer improvements or framing gaps as “optional polish.”
- **Context pressure:** Long E2E runs encourage **truncation**: document what was done, then **stop** instead of **starting the next loop in the same session**.

## 2. Ambiguous handoff vs completion

- **OPEN issues** were sometimes treated as **“session complete, next human/agent run continues.”** The user wanted **continuation until closure**, not a comfortable handoff after one pass.
- **Section E (E2E)** was sometimes **skipped or shortened** while A–D or docs were updated — the prompt allowed “file OPEN issue and stop,” which the agent used to **exit early**.

## 3. Missing mandatory artifacts

- Without a **single source of truth** for “weak spots still open,” the agent could **forget** or **under-report** gaps between turns.
- **AGENT_WEAK_PLACES.md** (see AGENT_PROMPT_FULL_CYCLE) fixes this: every gap is **listed**, **actionable**, and must be **cleared or explicitly blocked** before a valid stop.

## 4. “Improvement proposals” vs “work done”

- Stopping with **proposals** (“we could add X”) is **forbidden** as a terminal state: proposals mean **work remains** — either implement now or add a row to the weak-place registry with acceptance and **run the next loop**.

## 5. What we changed (summary)

| Gap | Mitigation |
|-----|------------|
| Subjective “no improvements” | **Registry + self-audit table** (claim / evidence / blocking) required before stop |
| Early stop after “good analysis” | **Mandatory auto-loop:** document weak → fix → re-verify **same session** when possible |
| Lost weak spots | **docs/AGENT_WEAK_PLACES.md** — OPEN rows block completion |
| Optional polish | Treat as **OPEN** until fixed or test proves acceptable |
| LLM wrong HTTP method on curls | **prompts.py** + E2E q5 text: method must match doc |

Review **docs/AGENT_PROMPT_FULL_CYCLE.md** for the authoritative loop and stop rules.
