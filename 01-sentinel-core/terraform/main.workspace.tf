# Log Analytics workspace that Sentinel runs on.
module "workspace" {
  source  = "Azure/avm-res-operationalinsights-workspace/azurerm"
  version = "0.5.1"

  name                = "law-soc-sentinel"
  location            = local.location
  resource_group_name = module.rg_sentinel.name
  enable_telemetry    = false

  log_analytics_workspace_sku = "PerGB2018"

  # 90 days is the retention Sentinel includes at no extra charge.
  log_analytics_workspace_retention_in_days = 90

  # Emergency brake only. Real cost control is filtering at the source
  # (rsyslog on the VM and the facilities chosen in the DCR).
  log_analytics_workspace_daily_quota_gb = 1

  # The AVM default is "false" for both, which would stop the agent from
  # sending logs and the portal from querying them. There is no private link
  # in this lab, so both stay on the public endpoint.
  log_analytics_workspace_internet_ingestion_enabled = "true"
  log_analytics_workspace_internet_query_enabled     = "true"
}
