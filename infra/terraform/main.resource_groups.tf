# Three resource groups so each identity can be scoped to one of them:
# the honeypot can be deleted on its own at the end, and Sentinel's service
# account only gets Automation Contributor on the automation group.

# Honeypot network and VM. Deleted at the end of the project.
resource "azurerm_resource_group" "honeypot" {
  name     = "RG-SOC-Honeypot"
  location = var.location
}

# Log Analytics workspace with Sentinel.
resource "azurerm_resource_group" "sentinel" {
  name     = "RG-SOC-Sentinel"
  location = var.location
}

# Empty for now. The Logic Apps playbooks are deployed here later.
resource "azurerm_resource_group" "automation" {
  name     = "RG-SOC-Automation"
  location = var.location
}
