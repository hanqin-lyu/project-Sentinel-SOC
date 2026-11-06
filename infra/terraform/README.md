# Terraform: honeypot, Sentinel and automation resource groups

> **Status: written locally, not yet validated or applied.** Run `terraform init && terraform validate && terraform plan` and read the plan before any apply.

The budget/cost alert was created manually in the Azure portal and is not managed here.

## What it creates

| Group (default name) | Resources |
|---|---|
| `RG-SOC-Honeypot` | VNet + subnet, NSG (attached to subnet), static public IP, NIC, Ubuntu 24.04 VM (SSH-key admin, system-assigned identity with no roles), cloud-init installing auditd + execve rule |
| `RG-SOC-Sentinel` | Log Analytics workspace (cap + 90-day retention), Sentinel onboarding (off by default), DCR `dcr-honeypot-syslog` with ingestion-time `transform_kql`, AMA extension, DCR association |
| `RG-SOC-Automation` | Empty group for Logic Apps playbooks (Phase 4) |

## NSG rule layout

| Dir | Priority | Rule | Notes |
|---|---|---|---|
| In | 100 | Allow admin port from `management_source_cidr` | Skipped if empty |
| In | 200 | `SOAR-Block-Attackers` (Deny) | Placeholder `192.0.2.1`; PB2 edits it; `ignore_changes` keeps Terraform from undoing live blocks |
| In | 300 | Allow TCP 22 from anywhere | The honeypot |
| Out | 100/110/120 | AzureMonitor 443, AzurePlatformDNS, AzurePlatformIMDS | |
| Out | 4000 | Deny Internet | Only when `lockdown_egress = true` |

## Usage

```bash
az login
cp terraform.tfvars.example terraform.tfvars   # fill in values
terraform init
terraform validate
terraform plan -out tfplan
terraform apply tfplan
```

Commit `.terraform.lock.hcl` after `init`. State, `tfvars` and plan files are git-ignored.

### Two-stage apply (egress lockdown)
1. First apply with `lockdown_egress = false` so cloud-init (apt) and the AMA extension can download.
2. Check cloud-init finished (`cloud-init status`) and the DCR association shows in the portal.
3. Set `lockdown_egress = true` and apply again.

## Manual steps that stay outside Terraform (Phase 1)
- Add the weak-password decoy account inside the OS (never in Terraform or tfvars).
- Move the admin sshd to `admin_ssh_port`. On Ubuntu 24.04 sshd is socket-activated, so an `ssh.socket` override is needed; check with `ss -tlnp`. Cloud images also ship `60-cloudimg-settings.conf` that disables password auth, which the decoy needs overridden.
- Forward auditd records to syslog (`local6`) so the DCR picks them up.
- Verify rows arrive in `Syslog` before enabling Sentinel (`enable_sentinel = true` starts the 31-day trial clock).

## Notes
- Provider pinned `~> 4.0`; 4.x needs `subscription_id` (set via variable).
- Setting `syslog_transform_kql = "source"` disables filtering, useful while baselining.
- Region/VM-size availability varies by subscription; change `location` / `vm_size` if creation fails.
