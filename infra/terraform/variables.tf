variable "subscription_id" {
  description = "Azure subscription ID to deploy into. Keep it in terraform.tfvars (git-ignored)."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region for every resource."
  type        = string
  default     = "australiaeast"
}

variable "extra_tags" {
  description = "Additional tags merged onto every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Resource groups
# ---------------------------------------------------------------------------
variable "rg_honeypot_name" {
  type    = string
  default = "RG-SOC-Honeypot"
}

variable "rg_sentinel_name" {
  type    = string
  default = "RG-SOC-Sentinel"
}

variable "rg_automation_name" {
  description = "Resource group that will hold the Logic Apps playbooks."
  type        = string
  default     = "RG-SOC-Automation"
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
variable "vnet_address_space" {
  type    = list(string)
  default = ["10.10.0.0/16"]
}

variable "subnet_address_prefix" {
  type    = string
  default = "10.10.1.0/24"
}

variable "management_source_cidr" {
  description = "Your public IP in CIDR form (for example 203.0.113.10/32). Allowed to reach the admin SSH port. Empty string = no admin SSH rule (administer through az vm run-command instead)."
  type        = string
  default     = ""

  validation {
    condition     = var.management_source_cidr == "" || (can(cidrhost(var.management_source_cidr, 0)) && var.management_source_cidr != "0.0.0.0/0")
    error_message = "management_source_cidr must be empty or a valid CIDR other than 0.0.0.0/0."
  }
}

variable "admin_ssh_port" {
  description = "Port the admin sshd listens on. Port 22 stays the honeypot. Configuring sshd to listen here is a Phase 1 step (see README)."
  type        = number
  default     = 2222
}

variable "lockdown_egress" {
  description = "false on the first apply so cloud-init and the extensions can download packages. Set true afterwards to deny outbound Internet except Azure Monitor."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Honeypot VM
# ---------------------------------------------------------------------------
variable "vm_name" {
  type    = string
  default = "vm-honeypot-01"
}

variable "vm_size" {
  description = "Small burstable size. Check availability in your region and subscription if creation fails."
  type        = string
  default     = "Standard_B2s"
}

variable "admin_username" {
  description = "Admin account (key-only). Avoid Azure reserved names such as admin, root, administrator."
  type        = string
  default     = "azureops"
}

variable "admin_ssh_public_key" {
  description = "Public SSH key for the admin account. The decoy account is created inside the OS in Phase 1, never here."
  type        = string

  validation {
    condition     = can(regex("^ssh-(rsa|ed25519) ", var.admin_ssh_public_key))
    error_message = "Provide an OpenSSH public key beginning with ssh-rsa or ssh-ed25519."
  }
}

# ---------------------------------------------------------------------------
# Log Analytics, Sentinel and collection
# ---------------------------------------------------------------------------
variable "workspace_name" {
  type    = string
  default = "law-soc-sentinel"
}

variable "retention_days" {
  type    = number
  default = 90
}

variable "daily_cap_gb" {
  description = "Backstop only. When reached, collection stops for the rest of the day. -1 = unlimited."
  type        = number
  default     = 1

  validation {
    condition     = var.daily_cap_gb == -1 || var.daily_cap_gb >= 0.023
    error_message = "daily_cap_gb must be -1 (unlimited) or at least 0.023."
  }
}

variable "enable_sentinel" {
  description = "Enabling Sentinel starts the 31-day free trial. Leave false until build day."
  type        = bool
  default     = false
}

variable "syslog_transform_kql" {
  description = "Ingestion-time transformation applied by the DCR. Set to \"source\" to keep everything, for example while baselining."
  type        = string
  default     = <<-KQL
    source
    | where ProcessName startswith "sshd"
         or ProcessName in ("sudo", "useradd", "usermod", "passwd")
         or Facility == "local6"
  KQL
}
