variable "subscription_id" {
  description = "Azure subscription ID. Set it in terraform.tfvars (git-ignored)."
  type        = string
}

variable "location" {
  description = "Azure region for every resource."
  type        = string
  default     = "australiaeast"
}

variable "admin_ssh_public_key" {
  description = "Public SSH key for the VM admin account."
  type        = string
}

variable "management_source_cidr" {
  description = "Your public IP as a /32 (for example 203.0.113.10/32). Only this address can reach the admin SSH port 2222. Empty = no admin rule."
  type        = string
  default     = ""
}

variable "lockdown_egress" {
  description = "false for the first apply (the VM must download packages). Set true afterwards to block outbound Internet."
  type        = bool
  default     = false
}
