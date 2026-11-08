# Terraform: honeypot, Sentinel and automation resource groups

Written but **not yet run or validated**. Run `terraform init`, `terraform validate` and `terraform plan` and read the plan before applying. The budget was created by hand in the portal and is not in this code.

## What it builds

| Resource group | Contents |
|---|---|
| `RG-SOC-Honeypot` | Network (VNet, subnet, NSG, public IP) and an Ubuntu 24.04 VM with auditd |
| `RG-SOC-Sentinel` | Log Analytics workspace with Sentinel turned on (starts the 31-day free trial) |
| `RG-SOC-Automation` | Empty. The playbooks go here later |

## Files

| File | What it holds |
|---|---|
| `terraform.tf`, `providers.tf` | Version requirements and the Azure provider |
| `variables.tf`, `outputs.tf` | The 5 inputs and 3 outputs |
| `main.resource_groups.tf` | The three resource groups |
| `main.network.tf` | VNet, subnet, NSG with its rules, public IP |
| `main.honeypot_vm.tf` | Network card and the VM (`cloud-init.yaml` installs auditd) |
| `main.sentinel.tf` | Workspace and the Sentinel switch |

## NSG rules

| Direction | Priority | Rule |
|---|---|---|
| In | 100 | Admin SSH on port 2222 from your IP only |
| In | 200 | `SOAR-Block-Attackers`: Deny. Holds a dummy address; the playbook edits it |
| In | 300 | Port 22 open to everyone (the honeypot) |
| Out | 100–120 | Allow Azure Monitor, Azure DNS and the metadata service |
| Out | 4000 | Deny the rest of the Internet, only when `lockdown_egress = true` |

## Use

```bash
az login
cp terraform.tfvars.example terraform.tfvars   # fill in the values
terraform init
terraform plan
terraform apply
```

Commit `.terraform.lock.hcl` after `init`. State and `terraform.tfvars` are git-ignored.

**Apply twice.** First with `lockdown_egress = false` so the VM can download packages and the connector can install the agent. Once logs are arriving, set it to `true` and apply again. Apply on build day, because Sentinel is turned on by the first apply.

## Done by hand afterwards

1. Create the weak-password decoy account inside the VM.
2. Move the admin SSH to port 2222. Ubuntu 24.04 starts sshd through a socket, so the port is changed in an `ssh.socket` override. Check with `ss -tlnp`.
3. Send auditd records to syslog (`local6`).
4. In the Defender portal, open Sentinel, Content hub, install the **Syslog** solution, open the **Syslog via AMA** connector and create a rule for the VM (facilities `auth`, `authpriv`, `local6`). The connector installs the agent.
5. Check rows appear in the `Syslog` table.
6. Set `lockdown_egress = true` and apply again.
