# Sentinel lives in its own resource group, so the honeypot (stack 02) can be
# deleted at the end without touching the workspace or its data.
locals {
  location = "australiaeast"
}

module "rg_sentinel" {
  source  = "Azure/avm-res-resources-resourcegroup/azurerm"
  version = "0.5.0"

  name             = "RG-SOC-Sentinel"
  location         = local.location
  enable_telemetry = false
}
