resource "azurerm_log_analytics_workspace" "soc" {
  name                = "law-soc-sentinel"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  daily_quota_gb      = 1 # emergency brake only, not real cost control
}

# Turns Sentinel on. This starts the 31-day free trial.
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "soc" {
  workspace_id = azurerm_log_analytics_workspace.soc.id
}

# Log collection is not set up here. After apply, install the Syslog solution
# from the Sentinel Content hub and use its "Syslog via AMA" connector, which
# creates the data collection rule and installs the agent on the VM.
