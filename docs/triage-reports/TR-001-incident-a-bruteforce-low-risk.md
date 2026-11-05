# TR-001: Incident A, SSH brute force with low threat score

> **Status: DRAFT TEMPLATE.** Every `[bracketed]` value is a placeholder. Replace it with real data from the simulated incident, and attach redacted screenshots under `docs/evidence/`. Nothing in this file is a measured result. Delete this note when the report is final.
>
> **Dependency to settle before building:** this scenario expects a brute-force-only incident to be created, automatically blocked and automatically closed. The current design keeps R1 alert-only (no incident) and does not block on a low enrichment score. See "Design decisions to confirm" at the end.

| Field | Value |
|---|---|
| Report ID | TR-001 |
| Incident | [Sentinel incident number and title] |
| Scenario | Password brute force only, low threat-intelligence score, automated block and closure |
| Severity / Status | [Low] / [Closed] |
| Classification | [Benign Positive – Suspicious but expected / True Positive – Low impact] |
| Detected | [UTC time] · [AEDT time] |
| Closed | [UTC time] · [AEDT time] |
| Analyst | [name] |
| Report date | [date] |
| Affected asset | [honeypot host name] |
| Attacker indicators | [defanged IP, usernames tried] |

## 1. Summary

[Two to four sentences. Example structure: On [date], [host] received [N] failed SSH password attempts from [defanged IP] over [M] minutes against [K] usernames. No login succeeded. Threat-intelligence scoring was low ([score]). The playbook added a time-limited network block and closed the incident without analyst action. Status: closed, block expires [date].]

## 2. Actions Taken

| Time (UTC) | Action | Performed by | Result |
|---|---|---|---|
| [time] | Alert raised by [rule name] and incident created | Sentinel | [incident number] |
| [time] | Tags and Tasks checklist added | Automation rule | [success / failure] |
| [time] | Enrichment query for [defanged IP] | PB1 | [score, country, verdict] |
| [time] | Decision branch evaluated | PB2 | [branch taken and reason] |
| [time] | NSG block added with TTL [N days] | PB2 | [success / failure, rule name] |
| [time] | Comment added summarising actions | PB6 | [success / failure] |
| [time] | Incident closed as [classification] | Playbook / Automation rule | [success / failure] |
| [time] | Block removed at TTL expiry | PB4 | [removed / still present] |

Every row must be traceable to a playbook run ID or an incident comment: [run IDs].

## 3. Findings

1. **Attack pattern.** [N] failed passwords from [defanged IP] between [time] and [time], across [M] usernames ([examples]). Evidence: [query name, screenshot file]. Confidence: [confirmed].
2. **No compromise.** No `Accepted password` event from this source or for the targeted accounts in the same period. Evidence: [query, screenshot]. Confidence: [confirmed].
3. **Reputation.** Threat-intelligence score [score] ([source]); [why this is treated as low risk]. Confidence: [likely].
4. **Scope.** Entity and investigation graph show [no other hosts or accounts involved]. Evidence: [screenshot]. Confidence: [confirmed].

Keep what the logs show separate from what you conclude. If something could not be confirmed, say so.

## 4. Decisions

| Decision | Reason | Alternative considered and rejected |
|---|---|---|
| Classify as [classification] | [reason] | [alternative] rejected because [reason] |
| Automatic NSG block with TTL [N days] | [reversible, low impact, supported by evidence] | [no block] rejected because [reason] |
| Close without analyst review | [no login, low score, no disruptive action taken] | [keep open] rejected because [reason] |
| Follow-up | [threshold tuning / watchlist update / none], owner [name] | |

## 5. References

- MITRE ATT&CK: T1110.001 Brute Force: Password Guessing, https://attack.mitre.org/techniques/T1110/001/ (add T1110.003 only if password spraying was observed).
- Sentinel analytics rule: [rule name and version]. Playbook runs: [run IDs].
- Microsoft Learn: Automate threat response with playbooks in Microsoft Sentinel, https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Microsoft Learn: Network security groups overview, https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview (rule changes affect new connections only).
- Evidence files: [docs/evidence/...].

## Design decisions to confirm (remove when settled)

- R1 is currently alert-only and creates no incident. This report needs either an R1 variant that opens a Low-severity incident above a sustained threshold, or the scenario must be driven through attacker-sim with that variant enabled.
- The decision table currently says a low or unknown score means no block. This report shows an automatic block on a low score. Decide which is intended; if blocking stays, the reason must be explained in section 4 (for example, block because the volume is abusive regardless of reputation).
