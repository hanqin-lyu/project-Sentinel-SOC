# Data collection rule for the honeypot's syslog. It is defined in code instead
# of through the Content hub "Syslog via AMA" connector, so it is deployed by
# the same pipeline as everything else. Stack 02 finds it by name and links
# the VM to it.
#
#   auth, authpriv  SSH logins and failures (R1, R2, R5)
#   local6          auditd records forwarded by honeypot-setup.sh (R3, R4)
module "dcr_honeypot_syslog" {
  source  = "Azure/avm-res-insights-datacollectionrule/azurerm"
  version = "0.1.0"

  name             = "dcr-honeypot-syslog"
  location         = local.location
  parent_id        = module.rg_sentinel.resource_id
  kind             = "Linux"
  enable_telemetry = false

  data_sources = {
    syslog = [{
      name           = "honeypot-syslog"
      facility_names = ["auth", "authpriv", "local6"]
      log_levels     = ["*"]
      streams        = ["Microsoft-Syslog"]
    }]
  }

  destinations = {
    log_analytics = [{
      name                  = "law-soc-sentinel"
      workspace_resource_id = module.workspace.resource_id
    }]
  }

  data_flows = [{
    streams      = ["Microsoft-Syslog"]
    destinations = ["law-soc-sentinel"]
  }]
}
