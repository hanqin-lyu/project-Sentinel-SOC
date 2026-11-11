# TR-001: Incident A, sustained SSH brute force, no login (P3)

> **Status: DRAFT TEMPLATE.** Every `[bracketed]` value is a placeholder. Replace it with real data from the simulated incident, and attach redacted screenshots under `docs/evidence/`. Nothing in this file is a measured result. Delete this note when the report is final.

| Field | Value |
|---|---|
| Report ID | TR-001 |
| Incident | [Sentinel incident number and title] |
| Scenario | Sustained password brute force, no login; no block; reviewed at the daily P3 check and closed by the analyst |
| Rule | R5 Sustained brute force |
| Priority / Severity / Status | P3 / [Low] / [Closed] |
| Classification | [Benign Positive – Suspicious but expected] (confirm which closure reason is used) |
| Detected | [UTC time] · [AEDT time] |
| Due (P3, same day) | [UTC time] · [AEDT time] |
| Acknowledged | [UTC time] · [AEDT time] |
| Closed | [UTC time] · [AEDT time] |
| Analyst | [name] |
| Report date | [date] |
| Affected asset | [honeypot host name] |
| Attacker indicators | [defanged IP, usernames tried] |

## 1. Summary

[Two to four sentences. Example structure: On [date], [host] received [N] failed SSH login attempts from [defanged IP] within 10 minutes against [K] usernames. No login succeeded. Threat-intelligence scoring was [score]. A Teams message with the P3 SLA was sent; the analyst reviewed the incident at [time] and closed the incident as [classification] with no block. Status: closed.]

## 2. Actions Taken

| Time (UTC) | Action | Performed by | Result |
|---|---|---|---|
| [time] | R5 fired and incident created | Sentinel | [incident number] |
| [time] | Enrichment query for [defanged IP] | PB1 (automatic) | [score, country, verdict] |
| [time] | P3 tag, due time comment, Teams message with P3 SLA | PB3 (automatic) | [success / failure] |
| [time] | Daily review of the issue and incident | [analyst] | [result] |
| [time] | Incident closed as [classification] with reason comment | PB9 (manual) | [success / failure] |

Every row must be traceable to a playbook run ID or an incident comment: [run IDs]. No NSG change was made; confirm with the Activity Log: [screenshot].

## 3. Findings

1. **Attack pattern.** [N] failed logins from [defanged IP] between [time] and [time], across [M] usernames ([examples]). Evidence: [query name, screenshot file]. Confidence: [confirmed].
2. **No compromise.** No `Accepted` login from this source in the same period or in the previous 24 hours. Evidence: [query, screenshot]. Confidence: [confirmed].
3. **Reputation.** Threat-intelligence score [score] ([source]); [why this is treated as low risk]. Confidence: [likely].
4. **Scope.** The entity and investigation graph show [no other hosts or accounts involved]. Evidence: [screenshot]. Confidence: [confirmed].

Keep what the logs show separate from what you conclude. If something could not be confirmed, say so.

## 4. Decisions

| Decision | Reason | Alternative considered and rejected |
|---|---|---|
| Classify as [classification] | [no login, expected internet scanning against an exposed service] | [True Positive – Suspicious Activity] rejected because [reason] |
| No network block | [no login; a block on rotating scanner IPs adds NSG rules with little protective value] | [block with TTL] rejected because [reason] |
| Daily review instead of an immediate response | [P3: no login, nothing to contain] | [respond within 30 minutes] rejected because [reason] |
| Follow-up | [threshold tuning / watchlist update / none], owner [name] | |

## 5. References

- MITRE ATT&CK: T1110.001 Brute Force: Password Guessing, https://attack.mitre.org/techniques/T1110/001/ (add T1110.003 only if password spraying was observed).
- Sentinel analytics rule: R5 [name and version]. Playbook runs: [run IDs].
- Microsoft Learn: Automate threat response with playbooks in Microsoft Sentinel, https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Evidence files: [docs/evidence/...].

## Evidence checklist (remove when complete)

- [ ] R5 incident page showing the alert, entities and timeline
- [ ] KQL result proving no successful login from the source
- [ ] Playbook run history for PB1, PB3 and PB9
- [ ] The Teams message and the incident comments
- [ ] Activity Log showing no NSG change
