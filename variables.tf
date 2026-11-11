locals {
  location = "australiaeast"
}

# Both inputs are set in GitHub (repository variable and secret) and reach
# Terraform as TF_VAR_* in the workflows.

variable "admin_ssh_public_key" {
  description = "Public SSH key for the VM admin account. GitHub variable ADMIN_SSH_PUBLIC_KEY."
  type        = string
}

variable "management_source_cidr" {
  description = "Owner's public IP as a /32. The only address that can reach admin SSH on port 2222, and an entry in the Trusted_IPs watchlist. Empty = neither. GitHub secret MANAGEMENT_SOURCE_CIDR."
  type        = string
  default     = ""
  # Hidden in plan output, which is posted to the PR job summary.
  sensitive = true
}
