# project-Sentinel-SOC

Closed-loop SOC automation on Microsoft Sentinel. An Azure SSH honeypot feeds Sentinel; custom KQL rules raise incidents; Logic Apps playbooks do every response step, automatic or run by the analyst, so each action leaves evidence.

Status: Sentinel, the honeypot and the first playbooks are deployed through the pipeline.

## Layout

| Path | What it holds |
|---|---|
| `.github/workflows/terraform.yml` | The CI/CD pipeline |
| `providers.tf` | Terraform and provider versions, backend, Azure sign-in |
| `variables.tf` | Inputs and the region |
| `outputs.tf` | Key outputs |
| `sentinel.tf` | Log Analytics workspace, Sentinel, syslog data collection rule (DCR), Trusted_IPs watchlist, analytics rules with their KQL, the `SOARBlocks_CL` block log with its endpoint and DCR |
| `honeypot.tf` | VNet, NSG, public IP, Ubuntu 24.04 VM, Azure Monitor Agent, DCR link, first-boot script |
| `soar.tf` | Playbooks, their API connection and roles, the Key Vault for their secrets, automation rules |
| `governance/` | Control plane, applied by hand and outside the pipeline: policy exemption on `rg-lab-honeypot` for the intentionally open SSH port |
| `docs/` | Phase 0 checklist, SLA (P1–P4 overview, plus the P2 and P3 SLA files sent with notifications), triage reports, the attack-simulation runbook |

All Terraform is one root module with one state, so `terraform plan` shows what each change adds and Terraform works out the order itself. The honeypot is removed at the end by a PR that deletes `honeypot.tf` and its outputs.

## Deployment

Same CI/CD design as [project-IaC-Azconfig](https://github.com/hanqin-lyu/project-IaC-Azconfig), with the same subscription, OIDC identities and Azure Policy.

| Event | Identity | Steps |
|---|---|---|
| Pull request | CI (read-only) | `fmt -check`, `validate`, Checkov (SARIF to the Security tab), gitleaks, `plan` (shown in the job summary). The PR is merged only after CI passes |
| Push to `main` | CD (read-write) | A deployment request for the `production-demo` environment; after the owner approves it, `apply` |

CI runs on every pull request, and `Terraform Plan Preview` is a required check on `main`. Apply runs only when a merge changes a Terraform file. State is in an Azure storage account. One-time setup is in [docs/phase0-checklist.md](docs/phase0-checklist.md).

## Design notes

- **One Terraform root.** The first version had three stacks with separate state, which needed lookups between stacks and a job to work out which stack a change touched. One root and one state removes all of that; `terraform plan` already compares the code with what is deployed.
- **DCR and agent in code.** The syslog DCR and the Azure Monitor Agent are Terraform, not the Content hub "Syslog via AMA" connector, so every part of the deployment goes through the same reviewed pipeline.
- **Azure Verified Modules.** Resources use the official AVM modules where one exists, pinned to exact versions with telemetry off. Sentinel onboarding, the DCR link and the playbook's block rule are native `azurerm` resources.
- **Block rule outside the NSG module.** The `SOAR-Block-Attackers` rule is edited by the playbook, so Terraform creates it once and ignores its address list. A later apply never wipes real blocks.
- **Admin SSH rule outside the NSG module.** The rule uses the owner's IP, a sensitive value, and the module runs `for_each` over its rule map, which cannot hold one. A separate rule keeps the IP hidden in the plan.
- **Connection flushing stays off.** NSG changes do not end an established SSH session, which is why the manual Contain host playbook (Run Command) exists.
- **One rule per priority.** R2 (P1), R4 (P2), R5 (P3), R1 (P4). R3 (tool download from auditd) and R6 (low-risk volume email) from the early plan are dropped, and R5 is no longer closed automatically. auditd is still collected as command evidence.
- **Rules count by ingestion time, not event time.** Each rule runs every 10 minutes. Its "last 10 minutes" window filters on `ingestion_time()`, because a syslog burst reaches the workspace a minute or two after it happens; a `TimeGenerated` window would run before the rows arrive and then slide past them, so a short attack could be missed entirely (R5 missed its first test this way). R1 also widens `query_period` to `PT20M`, so late rows are still fed to the query; R2, R4 and R5 already query a full day. The 24-hour brute-force history still uses `TimeGenerated`, where a 90-second delay does not matter.
- **Priority is severity, not an incident label.** PB2/PB3/PB4 first tried to add a `P1`/`P2`/`P3` label to the incident, but the label did not persist: because this workspace is used in the Defender portal, the incident is a Defender case, and Defender XDR re-syncs it (repeated `ModifiedBy = Microsoft Defender XDR` revisions) and overwrites labels set through the Sentinel API. A `PUT /Incidents` with `labels` returned success yet left `SecurityIncident.Labels` empty on a non-merged incident. So the label step was dropped. Priority is instead carried by the incident **severity** (R2 High = P1, R4 Medium = P2, R5 Low = P3), which sorts and filters natively, plus the Slack message and the acknowledge comment. Nothing is lost for triage, and the playbooks stay simpler.
- **R2 can raise two incidents for one attack; this is a test artifact.** R2 alerts on an Accepted login from an IP with a day of brute force behind it (`event_grouping = AlertPerResult`, per attacker IP, which is correct — one incident per IP), and re-runs every 10 minutes. The attack sim logs in twice from one IP (the hydra crack, then a manual SSH for the R4 step), so two alerts fire; incident grouping by the IP entity folds most, but a near-simultaneous pair can race into two incidents that the Defender portal then merges (the merged one is Closed and system-labelled `Redirected`), and the merge combines their PB1 comments. A real compromise has one successful login, so one incident with one enrichment. The grouping is already by IP and the duplicate is a merge artifact, not a re-run, so neither a rule change nor PB1 idempotency (PB1 runs once per incident) would prevent it; no code change is warranted.
- **R4 groups by account over a day.** Repeated sudo probing by the same account (`test`) within a day folds into one incident (by design, `by_entities = ["Account"]`, one-day lookback). A same-day re-test adds an alert to the open incident rather than creating a new one, so the automation rule — which triggers on incident creation — does not run again. To re-exercise PB2, run it manually on the incident, or close the incident first.
- **Every response step is a playbook.** Automatic playbooks do safe, reversible steps; disruptive steps are manual playbooks the analyst runs from the incident. Running a manual playbook replaces the Teams approval card from the early plan, and the run history records who did what and when. This is also least privilege: each playbook identity holds only the role its one job needs, and those assignments are Terraform. The human roles (Security Reader, SOC Responder, Owner) are a documented design, not assigned, because one person runs the lab. In the index each playbook is listed under the analytics rule it answers, with the automation rule that starts it.
- **Resource groups are made by hand.** Terraform looks up the three resource groups with data sources, so the CD identity needs no write access on the subscription. It has Contributor and Role Based Access Control Administrator on those three groups only, because playbook identities get roles in all three. Its OIDC credential also only works in the `production-demo` environment, after the owner approves the run.
- **The Playbooks tab's "missing permissions" is a false positive.** `sentinel_runs_playbooks` in `soar.tf` grants Microsoft Sentinel Automation Contributor to the Azure Security Insights service principal on `rg-core-automation`, which is the role that lets automation rules run playbooks. The Defender portal's Playbooks tab may still show "missing permissions" on every playbook, because its probe does not detect a grant made through IaC. The role is in fact present (confirmed with `az role assignment list`) and playbooks run (PB5 auto-ran from `AR-R2`). Do **not** click "Configure permissions": it would create a second, portal-managed assignment that drifts from Terraform.
- **Block log in a custom table.** PB5 writes each block, with its expiry, to `SOARBlocks_CL` through the Logs Ingestion API, and PB6 finds expired blocks with KQL. Incident comments were the other option, but they cannot be queried across incidents, and the table also feeds the workbook. The NSG rule is still what blocks. The DCR uses a separate data collection endpoint, because the AVM DCR module does not accept the `Direct` kind that would give the DCR its own endpoint. PB5 and PB6 call Azure with the HTTP action and their managed identity, so they need no extra API connection.
- **Key Vault for playbook secrets.** Third-party secrets (the AbuseIPDB API key now, the Slack webhook URL later) live in a Key Vault. Terraform creates the vault with RBAC authorization and grants each playbook identity the Key Vault Secrets User role, but the secret *values* are set by hand, so no secret is in the repo or the state: assign yourself Key Vault Secrets Officer on the vault, then `az keyvault secret set --vault-name <vault> --name abuseipdb-api-key --value <key>`. A playbook reads its secret at run time with the managed identity (audience `https://vault.azure.net`) and marks that step's data secure, so the value never shows in the run history.
- **Slack notifications over an incoming webhook (PB2, PB3, PB4).** The notifiers post to a Slack incoming webhook, not Teams. The webhook URL is a secret, so it lives in Key Vault as `slack-webhook-url`; each notifier reads it at run time with its managed identity and marks the fetch and the POST secure, so the URL never shows in the run history (the same pattern as PB1's AbuseIPDB key). A webhook can only post a message, not attach a file, so the P2 and P3 messages link to `docs/sla/P2-sla.md` and `docs/sla/P3-sla.md` in the repo instead of attaching them; the SLA doc stays the single source. Delivery is one HTTP POST with the managed identity, so there is no Slack API connection to manage. PB2 tags P2 and comments an acknowledge-by time 30 minutes from creation; PB3 tags P3 and states the daily-review target (R5 has no clock deadline); PB4 tags P1 and only notifies, because PB5 blocks the IP on the same incident.
- **AbuseIPDB enrichment (PB1).** AbuseIPDB is a crowd-sourced IP-reputation database: operators report the IPs that attacked them, and a lookup returns a 0-100 confidence score with the report count, country, ISP and usage type. PB1 looks up the attacker IP and writes this as an incident comment, so triage sees at a glance whether the source is a known bad actor. It is context, not a verdict: a high score flags a known-bad IP, but no reports does not prove an IP is safe (a fresh one has none), so it is one signal among several.
- **Honeypot findings in Checkov** are skipped inline with the reason "honeypot by design", never by turning the scan off.
- **One Checkov check is skipped in the pipeline: CKV_TF_1** (module source must be a git commit hash). AVM modules come from the Terraform Registry pinned to an exact version, and the modules nested inside AVM cannot be changed or skipped inline.

## Playbooks

Logic Apps playbooks and automation rules for Microsoft Sentinel, kept as Terraform in `soar.tf`. PB1, PB2, PB3, PB4, PB5, PB6, PB8 and PB9, a Key Vault for playbook secrets, and the automation rules AR-R2, AR-R4 and AR-R5 are built. AR-R2 runs PB1, PB5 and PB4; AR-R4 runs PB1 and PB2; AR-R5 runs PB1 and PB3. PB1, PB2, PB3, PB4, PB5, PB8 and PB9 are tested with real incidents; PB6's unblock is verified after the 24-hour TTL. The rest are planned.

### Rules

1. **Every response step is a playbook.** Each run leaves a run history and an incident comment, which is the evidence for the triage report.
2. **Least privilege.** Each playbook's managed identity holds only the role its one job needs, at the smallest scope (see [Identities](#identities)). People never change an incident, the NSG or the VM directly; they run a manual playbook. The human roles are a design only (see [Human roles](#human-roles)).
3. **Automation rules only start playbooks.** There is one automation rule per analytics rule. It starts that rule's automatic playbooks and changes nothing on the incident itself.
4. **Two kinds of playbook.** *Automatic* playbooks are started by an automation rule or a schedule and do only safe, reversible steps. *Manual* playbooks are run by the analyst from the incident page (Run playbook). Running one is the human decision, so disruptive steps such as ending a session are manual only.
5. **One job per playbook.**
6. **Settings are parameters.** Kill switch, block TTL and score threshold are workflow parameters, so behaviour changes without copying a playbook.
7. **Playbooks live in `soar.tf`.** Terraform deploys each one with the AVM module `Azure/avm-res-logic-workflow/azurerm`. Automation rules are native `azurerm` resources. API connections use `azapi`, because a managed identity connection needs `parameterValueType`, which `azurerm_api_connection` cannot set.
8. **No secrets in files.** Use managed identity, and Key Vault or an API connection for third-party keys.
9. **Templates are a starting point.** If a playbook starts from a Sentinel Content hub template (for example the Teams ones in SOAR Essentials), a comment in `soar.tf` names the template and what was changed.

### Index

| ID | Playbook | Class | Kind | Job |
|---|---|---|---|---|
| PB1 | Enrichment | Enrichment | Automatic | Look up the attacker IP and write the result as an incident comment |
| PB2 | Notify P2 | Orchestration | Automatic | Comment the acknowledge-by time and post the Slack message linking `docs/sla/P2-sla.md` |
| PB3 | Notify P3 | Orchestration | Automatic | Comment the acknowledge target and post the Slack message linking `docs/sla/P3-sla.md` |
| PB4 | Notify P1 | Response | Automatic | Post the Slack message |
| PB5 | Block IP | Response | Automatic | Add the attacker IP to the NSG block rule and log it with its expiry in `SOARBlocks_CL`; skip private, trusted and already-blocked IPs |
| PB6 | Block expiry | Response | Automatic (schedule) | Every hour, remove blocks past their expiry in `SOARBlocks_CL`, log the unblock and comment on the incident |
| PB7 | Contain host | Response | Manual | End the attacker's SSH session and lock the account through Run Command |
| PB8 | Report draft | Response | Manual | Post the incident facts as a comment to start the triage report |
| PB9 | Close incident | Response | Manual | Set the classification and write the closing reason as a comment |
| PB10 | Failure handler | Response | Automatic | When any playbook run fails, comment on the incident and send a Slack message |

### Response per analytics rule

#### R2 Compromise after brute force (P1)

| Step | Started by | Playbook |
|---|---|---|
| Incident created | Automation rule `AR-R2` | PB1 Enrichment, PB5 Block IP, PB4 Notify P1 |
| Block expiry reached | Schedule, every hour | PB6 Block expiry |
| Contain | Analyst | PB7 Contain host |
| Report and close | Analyst | PB8 Report draft, PB9 Close incident |

#### R4 Sudo probing (P2)

| Step | Started by | Playbook |
|---|---|---|
| Incident created | Automation rule `AR-R4` | PB1 Enrichment, PB2 Notify P2 |
| Contain, only if the user did more than probe | Analyst | PB7 Contain host |
| Report and close | Analyst | PB8 Report draft, PB9 Close incident |

#### R5 Sustained brute force (P3)

| Step | Started by | Playbook |
|---|---|---|
| Incident created | Automation rule `AR-R5` | PB1 Enrichment, PB3 Notify P3 |
| Close at the daily review | Analyst | PB9 Close incident |

#### R1 SSH brute force (P4)

Alert only, no incident, so there is no automation rule and no playbook. The alerts feed the Workbook.

PB10 Failure handler covers every playbook above.

### Identities

These role assignments are Terraform in `soar.tf`, so each one is in the plan and the diff.

| Identity | Role | Scope |
|---|---|---|
| PB1 Enrichment | Microsoft Sentinel Responder | `rg-soc-sentinel` |
| | Key Vault Secrets User (read the AbuseIPDB key) | The playbook Key Vault only |
| PB2, PB3, PB4 Notify | Microsoft Sentinel Responder (comment; PB4 only reads the trigger) | `rg-soc-sentinel` |
| | Key Vault Secrets User (read the Slack webhook URL) | The playbook Key Vault only |
| PB5 Block IP, PB6 Block expiry | Network Contributor | The `SOAR-Block-Attackers` rule only |
| | Monitoring Metrics Publisher (write to `SOARBlocks_CL`) | The `dcr-soar-blocks` DCR only |
| | Microsoft Sentinel Responder (comment; query Trusted_IPs and `SOARBlocks_CL`) | `rg-soc-sentinel` |
| PB7 Contain host | Virtual Machine Contributor | The honeypot VM only |
| | Microsoft Sentinel Responder | `rg-soc-sentinel` |
| PB8 Report draft, PB9 Close incident | Microsoft Sentinel Responder | `rg-soc-sentinel` |
| PB10 Failure handler | Logic App Operator (read the failed run) | `rg-core-automation` |
| | Microsoft Sentinel Responder | `rg-soc-sentinel` |
| Sentinel service account (Azure Security Insights) | Microsoft Sentinel Automation Contributor, so automation rules can start playbooks | `rg-core-automation` |

All are built-in roles limited by scope; there are no custom roles. Virtual Machine Contributor is wider than Run Command alone, but it reaches only the honeypot VM. The honeypot VM's own identity has no role.

### Human roles

Design only. The lab has one person, so a single owner account does all three jobs and these roles are not assigned.

```mermaid
flowchart LR
  R[Security Reader] -->|read| S[(Sentinel incidents)]
  A[SOC Responder] -->|read| S
  A -->|run PB7, PB8, PB9 only| M[Manual playbooks]
  AR[Automation rules] -->|start| AP[Automatic playbooks]
  M -->|managed identity| T[Incident, NSG rule, VM]
  AP -->|managed identity| T
  O[Owner, break-glass] -->|fix through a reviewed PR| TF[Terraform pipeline]
```

| Role | Would have | Cannot |
|---|---|---|
| Security Reader | Microsoft Sentinel Reader | Change anything |
| SOC Responder | Microsoft Sentinel Reader; Microsoft Sentinel Playbook Operator on PB7, PB8, PB9 only | Run automatic playbooks; edit incidents, the NSG or the VM directly |
| Owner | Owner, used only to fix the lab when something breaks | |
