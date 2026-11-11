# Triage reports

Structured incident reports in a fixed format: Summary, Actions Taken, Findings, Decisions, References.

| Report | Scenario |
|---|---|
| [TR-001](TR-001-incident-a-bruteforce-low-risk.md) | Incident A (P3): sustained brute force, no login, no block, daily review, closed by the analyst |
| [TR-002](TR-002-incident-b-high-severity-compromise.md) | Incident B (P1): successful compromise, `wget` download attempt, automatic block, analyst-run session termination |

Conventions: timestamps in UTC with AEDT alongside; IPs and URLs defanged (`203[.]0[.]113[.]10`, `hxxp://`); every finding tied to a query or a redacted screenshot in `docs/evidence/`; findings separate evidence from inference and state confidence.

Both reports are drafts until the incidents have been run. Replace every bracketed placeholder with real data.
