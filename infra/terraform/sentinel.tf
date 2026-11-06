resource "azurerm_log_analytics_workspace" "soc" {
  name                = var.workspace_name
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_days
  daily_quota_gb      = var.daily_cap_gb
  tags                = local.tags
}

# Starts the 31-day free trial, so it is off until enable_sentinel = true.
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "soc" {
  count        = var.enable_sentinel ? 1 : 0
  workspace_id = azurerm_log_analytics_workspace.soc.id
}

# Cost control lives here: facilities are limited, and transform_kql drops noise before
# it is billed. The daily cap above is only the backstop.
resource "azurerm_monitor_data_collection_rule" "syslog" {
  name                = "dcr-honeypot-syslog"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  kind                = "Linux"
  tags                = local.tags

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.soc.id
      name                  = "law-soc"
    }
  }

  data_sources {
    syslog {
      name           = "honeypot-syslog"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["auth", "authpriv", "local6"]
      log_levels     = ["Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
    }
  }

  data_flow {
    streams       = ["Microsoft-Syslog"]
    destinations  = ["law-soc"]
    transform_kql = var.syslog_transform_kql
  }
}

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.honeypot.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

resource "azurerm_monitor_data_collection_rule_association" "syslog" {
  name                    = "dcra-honeypot-syslog"
  target_resource_id      = azurerm_linux_virtual_machine.honeypot.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.syslog.id

  depends_on = [azurerm_virtual_machine_extension.ama]
}
