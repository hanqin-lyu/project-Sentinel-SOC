resource "azurerm_resource_group" "honeypot" {
  name     = var.rg_honeypot_name
  location = var.location
  tags     = local.tags
}

resource "azurerm_resource_group" "sentinel" {
  name     = var.rg_sentinel_name
  location = var.location
  tags     = local.tags
}

# Holds the Logic Apps playbooks (Phase 4). Sentinel's service account gets the
# "Microsoft Sentinel Automation Contributor" role on this group from the Sentinel
# playbook-permissions setting, not from here.
resource "azurerm_resource_group" "automation" {
  name     = var.rg_automation_name
  location = var.location
  tags     = local.tags
}
