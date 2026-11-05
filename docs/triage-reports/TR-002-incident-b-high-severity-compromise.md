# TR-002: Incident B, SSH compromise with malicious download

> **Status: DRAFT TEMPLATE.** Every `[bracketed]` value is a placeholder. Replace it with real data from the simulated incident, and attach redacted screenshots under `docs/evidence/`. Nothing in this file is a measured result. Delete this note when the report is final.

| Field | Value |
|---|---|
| Report ID | TR-002 |
| Incident | [Sentinel incident number and title] |
| Scenario | Successful brute force, `wget` download attempt, approval card, forced session termination |
| Severity / Status | [High] / [Closed or Active] |
| Classification | [True Positive – Suspicious Activity] |
| Detected | [UTC time] · [AEDT time] |
| Contained | [UTC time] · [AEDT time] |
| Analyst | [name] |
| Report date | [date] |
| Affected asset | [honeypot host name] |
| Attacker indicators | [defanged IP, decoy account, defanged download URL, file hash if captured] |

## 1. Summary

[Two to four sentences, readable by a non-technical reader. Example structure: On [date], [host] recorded a successful SSH login for [account] from [defanged IP] after [N] failed attempts. The attacker then ran [command] to fetch a file from [defanged URL]. The playbook added a time-limited network block at [time]. An analyst approved session termination and account lock at [time] through the [Teams / email] approval card. Status: [contained / pending review].]

## 2. Actions Taken

| Time (UTC) | Action | Performed by | Result |
|---|---|---|---|
| [time] | Incident created from [R2 / R3 rule names] | Sentinel | [incident number] |
| [time] | Tags and Tasks checklist added | Automation rule | [success / failure] |
| [time] | Enrichment query for [defanged IP] | PB1 | [score, country, verdict] |
| [time] | Decision branch evaluated | PB2 | [branch taken and reason] |
| [time] | NSG block added with TTL [N days] | PB2 | [success / failure, rule name] |
| [time] | Approval card sent for session kill and account lock | PB3 | [delivered to channel / mailbox] |
| [time] | Analyst response | [approver] | [approved / denied / timed out] |
| [time] | Active SSH session ended and decoy account locked via Run Command | PB3 | [exit status, session no longer present] |
| [time] | Report draft comment posted | PB6 | [success / failure] |
| [time] | Manual steps, if any | [analyst] | [result] |

Every row must be traceable to a playbook run ID or an incident comment: [run IDs].

## 3. Findings

1. **Initial access.** Brute force from [defanged IP]: [N] failures across [M] usernames between [time] and [time], then a successful login for [account] at [time]. Evidence: [R1/R2 queries, screenshot files]. Confidence: [confirmed].
2. **Post-login activity.** auditd recorded `[command]` at [time], an attempt to download from [defanged URL]. The honeypot's egress deny rule [blocked the download / did not apply]. Evidence: [R3 query, screenshot]. Confidence: [confirmed / likely].
3. **Persistence of the session.** After the NSG block at [time], the established SSH session [remained connected] until the Run Command step ended it at [time]. This confirms that NSG changes affect new connections only. Evidence: [screenshot, command output]. Confidence: [confirmed].
4. **Scope.** [Other accounts, hosts or source IPs involved, from the entity and investigation graph]. Evidence: [screenshot]. Confidence: [confirmed / possible].
5. **Reputation.** Threat-intelligence score [score] ([source]); weight given: [how much it influenced the decision]. Confidence: [likely].

Keep what the logs show separate from what you conclude. If something could not be confirmed, say so.

## 4. Decisions

| Decision | Reason | Alternative considered and rejected |
|---|---|---|
| Classify as True Positive – Suspicious Activity | [successful login plus download attempt] | [benign positive] rejected because [reason] |
| Escalate to P1 / High | [criteria: successful login and tool-download attempt] | [stay Medium] rejected because [reason] |
| Automatic NSG block with TTL [N days] | [reversible, supported by evidence] | [wait for approval] rejected because [reason] |
| Session kill and account lock on approval | [disruptive, so human-gated] | [fully automatic] rejected because [reason] |
| Approval outcome: [approved / denied / timed out] | [approver's reasoning] | |
| Follow-up | [rule tuning / new detection / none], owner [name] | |

## 5. References

- MITRE ATT&CK (keep only techniques actually observed): T1110.001 Brute Force: Password Guessing, https://attack.mitre.org/techniques/T1110/001/ · T1078.003 Valid Accounts: Local Accounts, https://attack.mitre.org/techniques/T1078/003/ · T1105 Ingress Tool Transfer, https://attack.mitre.org/techniques/T1105/ · T1548.003 Sudo and Sudo Caching, https://attack.mitre.org/techniques/T1548/003/ (only if sudo probing occurred).
- Sentinel analytics rules: [rule names and versions]. Playbook runs: [run IDs].
- Microsoft Learn: Automate threat response with playbooks in Microsoft Sentinel, https://learn.microsoft.com/azure/sentinel/automate-responses-with-playbooks
- Microsoft Learn: Network security groups overview, https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
- Evidence files: [docs/evidence/...].

## Evidence checklist (remove when complete)

- [ ] Incident page showing alerts, entities and timeline
- [ ] KQL results for R2 and R3 (redacted)
- [ ] Approval card as received, and the recorded response
- [ ] Playbook run history for PB1, PB2, PB3
- [ ] NSG rule showing the block and its TTL record
- [ ] Run Command output showing the session ended and the account locked
- [ ] Incident comments, including the PB6 draft
