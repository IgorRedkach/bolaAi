"""
Live API regressions for agent **E2E loop failures** only.

Issues from the full-cycle agent prompt that fail strict coverage, timeouts on
loop-specific docs, or bad person-style follow-ups are tracked as **[E2E-LOOP]**
in docs/ISSUES.md. Their autotests live **here**, not in test_issues_resolved.py.

Run separately when verifying a loop-failure fix:

    BOLA_AI_LIVE_URL=http://localhost:8000 PYTHONPATH=src \\
      pytest tests/test_e2e_loop_failures.py -v -s

See docs/E2E_TESTING.md and docs/AGENT_PROMPT_FULL_CYCLE.md (section E).

When you file **[E2E-LOOP] Issue N**, add ``test_e2e_loop_issue_N_<short>`` below
(unskipped) and remove or narrow this placeholder skip.
"""

import pytest


@pytest.mark.skip(
    reason="Remove when first [E2E-LOOP] regression is added; "
    "each OPEN [E2E-LOOP] issue should have a real test in this file."
)
def test_e2e_loop_failures_readme_placeholder():
    """Placeholder so the file is discoverable; replace with real loop regressions."""
    assert False
