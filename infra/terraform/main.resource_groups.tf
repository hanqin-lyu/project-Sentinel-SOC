resource "azurerm_resource_group" "honeypot" {
  name     = "RG-SOC-Honeypot"
  location = var.location
}

resource "azurerm_resource_group" "sentinel" {
  name     = "RG-SOC-Sentinel"
  location = var.location
}

# Empty for now. The Logic Apps playbooks are deployed here later.
resource "azurerm_resource_group" "automation" {
  name     = "RG-SOC-Automation"
  location = var.location
}
