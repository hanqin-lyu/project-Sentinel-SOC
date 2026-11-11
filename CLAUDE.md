# Project: Closed-Loop SOC Automation on Microsoft Sentinel

A solo portfolio project. An Azure SSH honeypot feeds Microsoft Sentinel (used in the Defender portal); custom KQL rules raise incidents; Logic Apps playbooks respond. The owner reads every change as a diff in VS Code and commits it himself.

## Hard rules (do not break, even if asked in passing)

1. **Never commit, push, stage, reset, clean or rebase.** Edit files only. The owner reviews the diff and commits.
2. **Never run `terraform apply`, `destroy`, `import` or `state`.** Apply runs only in GitHub Actions, after the owner approves the `production-demo` environment. The one exception is `governance/`, which the owner applies by hand after `az login`; never run it yourself. Allowed locally: `terraform fmt`, `terraform init -backend=false`, `terraform validate`. Do not run `terraform plan`; the PR's CI job posts the plan, and the owner pastes it.
3. **No Azure changes.** Do not run `az login`, and do not run any `az` command that creates, updates or deletes anything. Read-only `az ... show/list` is fine only if the owner is already logged in.
4. **No secrets.** Do not read or write `terraform.tfvars`, `*.tfstate`, `.env`, keys or `*.parameters.local.json`. Terraform inputs come from GitHub secrets and variables, never from files. Never put a subscription ID, tenant ID, key or real attacker IP in a file.
5. **Never invent results.** Metrics, incident data, timestamps and screenshots come from real runs. Until then use `[placeholders]`.
6. **The honeypot must stay isolated.** The VM identity has no role assignments, and port 22 is the only intentionally open inbound port.

## Keep it simple

- No variables, options or files "for later". If a value is not set by the owner, hard-code it.
- Everything is Terraform. Use an Azure Verified Module (AVM) where one exists, pinned to an exact version, with `enable_telemetry = false`; otherwise use the native `azurerm` resource.
- All Terraform is one root module at the repo root with one state: `providers.tf`, `variables.tf`, `outputs.tf`, `sentinel.tf`, `honeypot.tf`, `soar.tf`. Do not add stacks, subfolders or per-stack logic; the only separate root is `governance/` (control plane, own state, outside the pipeline). KQL and the first-boot script are heredocs in those files.
- Every incident response step is a playbook, one job each, so every action leaves evidence. Automatic playbooks do only safe, reversible steps; disruptive steps are manual playbooks the analyst runs. Automation rules only start playbooks (see the Playbooks section of `README.md`). Each playbook identity has only the role its job needs, in Terraform. Human roles (reader, responder, owner) are documented only, not assigned: one person runs the lab.
- Out of scope: AI/ML analysis, threat hunting, multi-workspace or multi-cloud collection. They belong to a separate project.

## Layout

- `.github/workflows/terraform.yml`: one pipeline (PR, CI identity: fmt, validate, Checkov, gitleaks, plan; merge to main, CD identity: apply after the owner approves `production-demo`)
- `sentinel.tf`: workspace, Sentinel, syslog DCR, Trusted_IPs watchlist, analytics rules, one per priority (R2 P1, R4 P2, R5 P3, R1 P4). The workbook goes here when built
- `honeypot.tf`: network, NSG, VM, AMA, DCR link, first-boot script
- `soar.tf`: automation resource group lookup now; playbooks and automation rules when built
- `governance/`: policy exemption for the honeypot's open SSH; applied by hand by the owner
- `README.md`: the whole design, including the playbook index
- `docs/`: phase 0 checklist, SLA (P1–P4 overview, plus the P2 and P3 SLA files sent with notifications), triage reports (drafts with placeholders)
- Nothing is applied yet. State is in an Azure storage account the owner created by hand. The three resource groups are also made by hand and looked up with data sources; the CD identity has Contributor and RBAC Administrator on those groups only. Playbook identities use built-in roles limited by scope, no custom roles

## Writing

- Repo files are in English, short and plain. The owner writes to you in Chinese; reply in Chinese.
- Triage reports: UTC with AEDT alongside, IPs and URLs defanged (`203[.]0[.]113[.]10`, `hxxp://`).
- The Word plan (`SIEM_Honeypot_SOC_Closed_Loop.docx`) is the early plan, not a fixed spec. The design changes as the project goes; a sound change does not need to match the Word plan. Record notable design changes in the README's Design notes.
