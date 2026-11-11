# ---------------------------------------------------------------------------
# Resource group
# ---------------------------------------------------------------------------
# Everything of the honeypot is in this one resource group, so it can be
# deleted at the end of the project without touching Sentinel.
locals {
  # false for the first apply: the VM must download packages and the agent.
  # Once logs arrive in Sentinel, change to true in a PR to block outbound
  # Internet.
  lockdown_egress = false
}

# Created by hand, so the pipeline needs no subscription-level write access.
data "azurerm_resource_group" "honeypot" {
  name = "rg-lab-honeypot"
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
# Isolated network for the honeypot: one VNet, one subnet with the NSG on it,
# and a static public IP. Nothing is peered with any other network.

module "vnet" {
  source  = "Azure/avm-res-network-virtualnetwork/azurerm"
  version = "0.23.0"

  name             = "vnet-honeypot"
  location         = local.location
  parent_id        = data.azurerm_resource_group.honeypot.id
  address_space    = ["10.10.0.0/16"]
  enable_telemetry = false

  subnets = {
    honeypot = {
      name             = "snet-honeypot"
      address_prefixes = ["10.10.1.0/24"]
      # The NSG sits on the subnet, not the NIC, so all rules are in one place.
      network_security_group = {
        id = module.nsg.resource_id
      }
    }
  }
}

# Standard SKU blocks all inbound traffic unless an NSG rule allows it.
# Kept outside the VM module so the address survives a VM rebuild.
module "pip" {
  source  = "Azure/avm-res-network-publicipaddress/azurerm"
  version = "0.2.1"

  name                = "pip-honeypot"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.honeypot.name
  allocation_method   = "Static"
  sku                 = "Standard"
  enable_telemetry    = false
}

# ---------------------------------------------------------------------------
# NSG rules (lower number is checked first)
#   In  100   admin SSH on port 2222, from the owner's IP only (separate resource below)
#   In  200   SOAR-Block-Attackers, edited by the playbook (separate resource below)
#   In  300   port 22 open to everyone: this is the honeypot
#   Out 100   Azure Monitor (the agent sends logs here)
#   Out 4000  deny Internet, only when lockdown_egress = true
#             (Azure's default rule 65001 would otherwise allow it)
# Azure DNS and the metadata service need no rule: NSGs do not filter them, and
# their service tags accept Deny only.
# ---------------------------------------------------------------------------
locals {
  egress_lockdown_rule = local.lockdown_egress ? {
    deny_internet_out = {
      name                       = "Deny-Internet-Out"
      priority                   = 4000
      direction                  = "Outbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "Internet"
    }
  } : {}

  static_rules = {
    # The one port meant to be open to the Internet. Attackers land here.
    allow_honeypot_ssh = {
      name                       = "Allow-Honeypot-SSH-Any"
      priority                   = 300
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
    allow_azure_monitor_out = {
      name                       = "Allow-AzureMonitor-Out"
      priority                   = 100
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "443"
      source_address_prefix      = "*"
      destination_address_prefix = "AzureMonitor"
    }
  }
}

# Connection flushing stays off (the module default). With it on, any rule
# change would drop established sessions, and the test "an established SSH
# session survives an NSG change" would no longer show why the playbook needs
# the Run Command step.
module "nsg" {
  source  = "Azure/avm-res-network-networksecuritygroup/azurerm"
  version = "0.6.0"

  name             = "nsg-honeypot"
  location         = local.location
  parent_id        = data.azurerm_resource_group.honeypot.id
  enable_telemetry = false

  security_rules = merge(local.static_rules, local.egress_lockdown_rule)
}

# The playbook rewrites this rule's address list, so it is not part of the
# module: Terraform creates it with a dummy address (192.0.2.1 is a
# documentation range) and then ignores the list, so a later apply never wipes
# real blocks. The module always ignores the NSG's own rule list, so this
# separate rule does not conflict with it.
resource "azurerm_network_security_rule" "soar_block" {
  name                        = "SOAR-Block-Attackers"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefixes     = ["192.0.2.1"]
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.honeypot.name
  network_security_group_name = module.nsg.name

  lifecycle {
    ignore_changes = [source_address_prefixes]
  }
}

# The owner's IP is sensitive, and the module runs for_each over its rule map,
# which cannot hold a sensitive value. So this rule is a separate resource too.
# Reachable only after sshd also listens on 2222 (manual step, README).
resource "azurerm_network_security_rule" "admin_ssh" {
  # count cannot use a sensitive value; only "is it set" is revealed.
  count = nonsensitive(var.management_source_cidr == "") ? 0 : 1

  name                        = "Allow-Admin-SSH-From-Mgmt"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "2222"
  source_address_prefix       = var.management_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.honeypot.name
  network_security_group_name = module.nsg.name
}

# ---------------------------------------------------------------------------
# First-boot script
# ---------------------------------------------------------------------------
locals {
  # Runs once on first boot through cloud-init.
  honeypot_setup = <<SCRIPT
#!/bin/bash
# First-boot setup for the honeypot, passed to the VM as custom data and run
# once by cloud-init.
#
#   1. auditd logs every command run by real login users (auid >= 1000).
#   2. auditd records are forwarded to syslog facility local6, which the DCR
#      collects as command evidence for investigations (no rule reads it).
#   3. rsyslog drops audit record types not needed as evidence, to cut ingestion.
#
# Not done here, by design (manual steps in the README):
#   - the weak-password decoy account (its password must never be in the repo)
#   - the extra sshd listener on port 2222 for admin access
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y auditd audispd-plugins

# 1. Command logging. auid 4294967295 means "no login user" (daemons).
cat > /etc/audit/rules.d/exec.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec_cmd
EOF

# 2. Forward audit records to syslog local6.
cat > /etc/audit/plugins.d/syslog.conf <<'EOF'
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
EOF

# 3. Drop record types with no detection value. The file sorts before the
#    agent's own rsyslog file, so dropped lines never reach Sentinel.
#    Revisit after the 48-hour ingestion review, once the real format is seen.
cat > /etc/rsyslog.d/05-honeypot-filter.conf <<'EOF'
if $syslogfacility-text == 'local6' and ($msg contains 'type=CWD' or $msg contains 'type=PATH' or $msg contains 'type=EOE') then stop
EOF

augenrules --load
# auditd refuses a normal restart; HUP makes it re-read its plugin config.
systemctl kill --signal=HUP auditd.service
systemctl restart rsyslog
SCRIPT
}

# ---------------------------------------------------------------------------
# VM
# ---------------------------------------------------------------------------
# The honeypot VM: Ubuntu 24.04 with a key-only admin account, auditd and the
# Azure Monitor Agent.
module "vm" {
  source  = "Azure/avm-res-compute-virtualmachine/azurerm"
  version = "0.21.0"

  name                = "vm-honeypot-01"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.honeypot.name
  os_type             = "Linux"
  # Same 2 vCPU and 4 GB as B2s, which has no capacity in this region.
  sku_size         = "Standard_B2als_v2"
  enable_telemetry = false

  # One VM, no need to pin an availability zone.
  zone = null

  # The admin account uses a key. The weak-password decoy account is created
  # inside the VM by hand later, never in Terraform. Turning password login
  # off here also turns it off in sshd, so the decoy needs password login
  # switched back on for that account by hand.
  account_credentials = {
    admin_credentials = {
      username                           = "azureops"
      ssh_keys                           = [var.admin_ssh_public_key]
      generate_admin_password_or_ssh_key = false
    }
    password_authentication_disabled = true
  }

  # Needed by the monitoring agent. No role is assigned to it on purpose, so a
  # hacked honeypot cannot call Azure APIs.
  managed_identities = {
    system_assigned = true
  }

  # Off: it needs the EncryptionAtHost feature registered on the subscription,
  # and the honeypot disk holds nothing worth protecting. The platform still
  # encrypts the disk at rest.
  encryption_at_host_enabled = false

  os_disk = {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference = {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  network_interfaces = {
    nic = {
      name = "nic-honeypot"
      ip_configurations = {
        ipconfig = {
          name                          = "ipconfig-honeypot"
          private_ip_subnet_resource_id = module.vnet.subnets["honeypot"].resource_id
          public_ip_address_resource_id = module.pip.resource_id
        }
      }
    }
  }

  # Serial console access if SSH breaks. Uses a managed storage account.
  boot_diagnostics = true

  # Runs once on first boot: auditd, audit-to-syslog forwarding, rsyslog
  # filter. Changing the script replaces the VM.
  custom_data = base64encode(local.honeypot_setup)

  # Azure Monitor Agent. It sends syslog to the workspace using the DCR that
  # is linked at the end of this file.
  extensions = {
    ama = {
      name                       = "AzureMonitorLinuxAgent"
      publisher                  = "Microsoft.Azure.Monitor"
      type                       = "AzureMonitorLinuxAgent"
      type_handler_version       = "1.0"
      auto_upgrade_minor_version = true
      automatic_upgrade_enabled  = true
    }
  }
}

# ---------------------------------------------------------------------------
# Log collection
# ---------------------------------------------------------------------------
# Links the VM to the syslog DCR in sentinel.tf.
resource "azurerm_monitor_data_collection_rule_association" "honeypot_syslog" {
  name                    = "dcra-honeypot-syslog"
  target_resource_id      = module.vm.resource_id
  data_collection_rule_id = module.dcr_honeypot_syslog.resource_id
}
