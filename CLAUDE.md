# Project: Closed-Loop SOC Automation on Microsoft Sentinel

A solo portfolio project. An Azure SSH honeypot feeds Microsoft Sentinel (used in the Defender portal); custom KQL rules raise incidents; Logic Apps playbooks respond. The owner reads every change as a diff in VS Code and commits it himself.

## Hard rules (do not break, even if asked in passing)

1. **Never commit, push, stage, reset, clean or rebase.** Edit files only. The owner reviews the diff and commits.
2. **Never run `terraform apply`, `destroy`, `import` or `state`.** Apply runs only in GitHub Actions, after the owner approves the `production-demo` environment. Allowed locally: `terraform fmt`, `terraform init -backend=false`, `terraform validate`. Do not run `terraform plan`; the PR's CI job posts the plan, and the owner pastes it.
3. **No Azure changes.** Do not run `az login`, and do not run any `az` command that creates, updates or deletes anything. Read-only `az ... show/list` is fine only if the owner is already logged in.
4. **No secrets.** Do not read or write `terraform.tfvars`, `*.tfstate`, `.env`, keys or `*.parameters.local.json`. Terraform inputs come from GitHub secrets and variables, never from files. Never put a subscription ID, tenant ID, key or real attacker IP in a file.
5. **Never invent results.** Metrics, incident data, timestamps and screenshots come from real runs. Until then use `[placeholders]`.
6. **The honeypot must stay isolated.** The VM identity has no role assignments, and port 22 is the only intentionally open inbound port.

## Keep it simple

- No variables, options or files "for later". If a value is not set by the owner, hard-code it.
- Everything is Terraform. Use an Azure Verified Module (AVM) where one exists, pinned to an exact version, with `enable_telemetry = false`; otherwise use the native `azurerm` resource.
- Terraform file names in every stack: `terraform.tf`, `providers.tf`, `variables.tf`, `outputs.tf`, `main.<topic>.tf`.
- Stacks link to each other only through data sources looked up by fixed names, never `terraform_remote_state`. Dependency order: 01 ← 02 ← 03.
- One job per playbook. Steps that need no external call go in a Sentinel automation rule (see `03-automation-soar/README.md`).
- Out of scope: AI/ML analysis, threat hunting, multi-workspace or multi-cloud collection. They belong to a separate project.

## Layout

- `.github/workflows/`: one pipeline per stack (PR: CI identity, fmt, validate, Checkov, plan; main: CD identity, approved apply)
- `01-sentinel-core/terraform/`: workspace, Sentinel, syslog DCR. Analytics rules, watchlist and workbook go in `01-sentinel-core/` when built
- `02-infrastructure-honeypot/`: network, NSG, VM, AMA, DCR link; `scripts/honeypot-setup.sh` runs on first boot
- `03-automation-soar/`: automation resource group now; playbooks and automation rules when built. `README.md` is the playbook index
- `docs/`: phase 0 checklist, SLA (P1–P4), triage reports (drafts with placeholders)
- Nothing is applied yet. State is in an Azure storage account the owner created by hand

## Writing

- Repo files are in English, short and plain. The owner writes to you in Chinese; reply in Chinese.
- Triage reports: UTC with AEDT alongside, IPs and URLs defanged (`203[.]0[.]113[.]10`, `hxxp://`).
- The Word plan (`SIEM_Honeypot_SOC_Closed_Loop.docx`) is the early plan, not a fixed spec. The design changes as the project goes; a sound change does not need to match the Word plan. Record notable design changes in the README's Design notes.
