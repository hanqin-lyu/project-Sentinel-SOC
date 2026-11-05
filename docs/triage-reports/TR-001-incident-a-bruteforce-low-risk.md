# TR-001: Incident A, sustained SSH brute force with low threat score

> **Status: DRAFT TEMPLATE.** Every `[bracketed]` value is a placeholder. Replace it with real data from the simulated incident, and attach redacted screenshots under `docs/evidence/`. Nothing in this file is a measured result. Delete this note when the report is final.

| Field | Value |
|---|---|
| Report ID | TR-001 |
| Incident | [Sentinel incident number and title] |
| Scenario | Sustained password brute force, no login, low threat-intelligence score; no block, automatic closure, data recorded |
| Rule | R5 Sustained brute force |
| Severity / Status | [Low] / [Closed automatically] |
| Classification | [Benign Positive – Suspicious but expected] (confirm which closure reason is used) |
| Detected | [UTC time] · [AEDT time] |
| Closed | [UTC time] · [AEDT time] |
| Analyst | [name; reviewed after closure, no action needed during handling] |
| Report date | [date] |
| Affected asset | [honeypot host name] |
| Attacker indicators | [defanged IP, usernames tried] |

## 1. Summary

[Two to four sentences. Example structure: On [date], [host] received [N] failed SSH password attempts from [defanged IP] within 10 minutes against [K] usernames. No login succeeded. Threat-intelligence scoring was low ([score]). No network block was applied. The playbook recorded the event with a comment and the tag AutoClosed-LowRisk and closed the incident automatically at [time]. Status: closed; counted towards the low-risk volume threshold ([count] of [threshold] in the last 24 hours).]

## 2. Actions Taken

| Time (UTC) | Action | Performed by | Result |
|---|---|---|---|
| [time] | R5 fired and incident created | Sentinel | [incident number] |
| [time] | Tags and Tasks checklist added | Automation rule | [success / failure] |
| [time] | Enrichment query for [defanged IP] | PB1 | [score, country, verdict] |
| [time] | Decision branch evaluated: low score, no login, no block | PB2 | [branch taken and reason] |
| [time] | Comment added summarising evidence and decision | PB2 / PB6 | [success / failure] |
| [time] | Tag AutoClosed-LowRisk added | PB2 | [success / failure] |
| [time] | Incident closed as [classification] | PB2 | [success / failure] |
| [time] | Low-risk volume counted by the R6 query | R6 alert rule | [count of threshold] |
| [time] | Email sent once the threshold was reached (only if it was) | R6 alert rule and action group | [sent / not triggered] |

Every row must be traceable to a playbook run ID or an incident comment: [run IDs]. No NSG change was made; confirm with the Activity Log: [screenshot].

## 3. Findings

1. **Attack pattern.** [N] failed passwords from [defanged IP] between [time] and [time], across [M] usernames ([examples]). Evidence: [query name, screenshot file]. Confidence: [confirmed].
2. **No compromise.** No `Accepted password` event from this source or for the targeted accounts in the same period or in the previous 24 hours. Evidence: [query, screenshot]. Confidence: [confirmed].
3. **Reputation.** Threat-intelligence score [score] ([source]); [why this is treated as low risk]. Confidence: [likely].
4. **Scope.** The entity and investigation graph show [no other hosts or accounts involved]. Evidence: [screenshot]. Confidence: [confirmed].
5. **Volume context.** [Count] low-risk incidents were auto-closed in the previous 24 hours, against the R6 threshold of [threshold]. Evidence: [query, Workbook screenshot]. Confidence: [confirmed].

Keep what the logs show separate from what you conclude. If something could not be confirmed, say so.

## 4. Decisions

| Decision | Reason | Alternative considered and rejected |
|---|---|---|
| Classify as [classification] | [no login, low score, expected internet scanning against an exposed service] | [True Positive – Suspicious Activity] rejected because [reason] |
| No network block | [low score; a block on rotating scanner IPs adds NSG rules with little protective value] | [automatic block with TTL] rejected because [reason] |
| Close automatically without analyst review | [no login, no disruptive action, data retained in SecurityIncident] | [keep open for review] rejected because [reason] |
| Record and count rather than discard | [closed incidents keep their evidence and feed the R6 volume threshold] | [delete or suppress the alert] rejected because [reason] |
| Email only above the volume threshold | [individual low-risk events are noise; a spike is worth attention] | [email per incident] rejected because [reason] |
| Follow-up | [threshold tuning / watchlist update / none], owner [name] | |

## 5. References

- MITRE ATT&CK: T1110.001 Brute Force: Password Guessing, https://attack.mitre.org/techniques/T1110/001/ (add T1110.003 only if password spraying was observed).
- Sentinel analytics rule: R5 [name and version]. Azure Monitor alert rule: R6 [name], action group [name]. Playbook runs: [run IDs].
- Microsoft Learn: Automate threat response with playbooks in Microsoft Sentinel, https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Evidence files: [docs/evidence/...].

## Evidence checklist (remove when complete)

- [ ] R5 incident page showing the alert, entities and timeline
- [ ] KQL result proving no successful login from the source
- [ ] Playbook run history for PB1 and PB2
- [ ] Incident status Closed with classification and the AutoClosed-LowRisk tag
- [ ] Activity Log showing no NSG change
- [ ] R6 query result with the count against the threshold, and the email when triggered
