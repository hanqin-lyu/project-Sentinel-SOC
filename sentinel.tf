# ---------------------------------------------------------------------------
# Resource group and workspace
# ---------------------------------------------------------------------------
# Sentinel lives in its own resource group, so the honeypot can be deleted at
# the end without touching the workspace or its data.
# Created by hand, so the pipeline needs no subscription-level write access.
data "azurerm_resource_group" "sentinel" {
  name = "rg-soc-sentinel"
}

# Log Analytics workspace that Sentinel runs on.
module "workspace" {
  source  = "Azure/avm-res-operationalinsights-workspace/azurerm"
  version = "0.5.1"

  name                = "law-soc-sentinel"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.sentinel.name
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

  # No shared-key access. The agent and the portal use Entra ID; nothing here
  # needs the workspace keys. (The AVM description of this input reads the
  # other way round; it maps to azurerm local_authentication_enabled.)
  log_analytics_workspace_local_authentication_enabled = false
}

# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------
# Turns Sentinel on for the workspace. This starts the 31-day free trial, so
# merge the PR that first applies this on build day.
# No AVM module covers Sentinel onboarding, so this is the native resource.
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "soc" {
  workspace_id = module.workspace.resource_id
}

# ---------------------------------------------------------------------------
# Syslog collection
# ---------------------------------------------------------------------------
# Data collection rule for the honeypot's syslog. It is defined in code instead
# of through the Content hub "Syslog via AMA" connector, so it is deployed by
# the same pipeline as everything else. honeypot.tf links the VM to it.
#
#   auth, authpriv  SSH logins and failures, sudo refusals (R1, R2, R4, R5)
#   local6          auditd command records forwarded by the first-boot script
#                   (evidence for investigation; no rule reads them)
module "dcr_honeypot_syslog" {
  source  = "Azure/avm-res-insights-datacollectionrule/azurerm"
  version = "0.1.0"

  name             = "dcr-honeypot-syslog"
  location         = local.location
  parent_id        = data.azurerm_resource_group.sentinel.id
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

# ---------------------------------------------------------------------------
# Trusted_IPs watchlist
# ---------------------------------------------------------------------------
# Trusted_IPs: addresses that never raise an alert. Every analytics rule starts
# by excluding them, and the automation rule closes any stray incident
# from them. It cuts false positives, not ingestion cost.
resource "azurerm_sentinel_watchlist" "trusted_ips" {
  name                       = "Trusted_IPs"
  display_name               = "Trusted IPs"
  description                = "Addresses excluded from every analytics rule."
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  item_search_key            = "IPAddress"
}

# The owner's admin IP, from the same GitHub secret as the admin SSH rule, so
# the address is never written in the repo.
resource "azurerm_sentinel_watchlist_item" "owner" {
  # count cannot use a sensitive value; only "is it set" is revealed.
  count = nonsensitive(var.management_source_cidr == "") ? 0 : 1

  watchlist_id = azurerm_sentinel_watchlist.trusted_ips.id
  properties = {
    IPAddress = split("/", var.management_source_cidr)[0]
    Reason    = "Owner admin access"
    Owner     = "owner"
  }
}

# ---------------------------------------------------------------------------
# Analytics rules
# ---------------------------------------------------------------------------
# Scheduled analytics rules, one per priority. Every rule runs every 10 minutes
# and makes one alert per result row. All response after the incident is
# created is done by playbooks (soar.tf).
#
# Rule  Severity       Priority  Output
# R2    High           P1        incident
# R4    Medium         P2        incident
# R5    Low            P3        incident
# R1    Informational  P4        alert only, feeds the workbook

resource "azurerm_sentinel_alert_rule_scheduled" "r1_ssh_brute_force" {
  name                       = "r1-ssh-brute-force"
  display_name               = "R1 SSH brute force"
  description                = "10 or more failed SSH logins from one IP in 10 minutes. Alert only."
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  severity                   = "Informational"
  query                      = <<-KQL
    // R1 SSH brute force (T1110.001, T1110.003)
    // 10 or more failed SSH logins from one IP in 10 minutes. Alert only, no
    // incident; it feeds the workbook (P4).
    // Password login is allowed only for the decoy account, so other usernames show
    // up as "Invalid user" or "Connection closed by authenticating user", not as
    // "Failed password". All three count as a failure. Tune after real data.
    let Trusted = _GetWatchlist('Trusted_IPs') | project SearchKey;
    Syslog
    | where TimeGenerated > ago(10m)
    | where Facility in ("auth", "authpriv") and ProcessName in ("sshd", "sshd-session")
    | where SyslogMessage has_any ("Failed password", "Invalid user", "Connection closed by authenticating user")
    | extend SourceIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage),
             User = extract(@"(?:Failed password for (?:invalid user )?|Invalid user |authenticating user )(\S+)", 1, SyslogMessage)
    | where isnotempty(SourceIP) and SourceIP !in (Trusted)
    | summarize FailedCount = count(), DistinctUsers = dcount(User), Users = tostring(make_set(User, 10))
        by SourceIP, HostName = Computer
    | where FailedCount >= 10
  KQL
  query_frequency            = "PT10M"
  query_period               = "PT10M"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  # Public SSH is scanned all day by rotating IPs, so R1 never opens an incident.
  incident {
    create_incident_enabled = false
    grouping {
      enabled = false
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "HostName"
    }
  }

  custom_details = {
    FailedCount   = "FailedCount"
    DistinctUsers = "DistinctUsers"
    Users         = "Users"
  }

  depends_on = [azurerm_sentinel_watchlist.trusted_ips]
}

resource "azurerm_sentinel_alert_rule_scheduled" "r2_compromise_after_brute_force" {
  name                       = "r2-compromise-after-brute-force"
  display_name               = "R2 Compromise after brute force"
  description                = "Successful password login from an IP with 10 or more failed SSH logins in the last 24 hours."
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  severity                   = "High"
  query                      = <<-KQL
    // R2 Compromise after brute force (T1078.003, T1021.004)
    // A successful password login in the last 10 minutes from an IP with 10 or
    // more failed SSH logins in the last 24 hours. High incident (P1).
    let Trusted = _GetWatchlist('Trusted_IPs') | project SearchKey;
    let SshAuth = Syslog
        | where TimeGenerated > ago(1d)
        | where Facility in ("auth", "authpriv") and ProcessName in ("sshd", "sshd-session")
        | extend SourceIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
        | where isnotempty(SourceIP) and SourceIP !in (Trusted);
    let BruteForcers = SshAuth
        | where SyslogMessage has_any ("Failed password", "Invalid user", "Connection closed by authenticating user")
        | summarize FailedCount = count(), FirstFail = tostring(min(TimeGenerated)) by SourceIP
        | where FailedCount >= 10;
    SshAuth
    | where TimeGenerated > ago(10m)
    | where SyslogMessage startswith "Accepted password for "
    | extend User = extract(@"^Accepted password for (\S+) from", 1, SyslogMessage)
    | join kind=inner BruteForcers on SourceIP
    | project TimeGenerated, SourceIP, User, HostName = Computer, FailedCount, FirstFail
  KQL
  query_frequency            = "PT10M"
  query_period               = "P1D"
  tactics                    = ["InitialAccess", "LateralMovement"]
  techniques                 = ["T1078", "T1021"]

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  # Alerts for the same attacker IP within a day go into one incident.
  incident {
    create_incident_enabled = true
    grouping {
      enabled                = true
      lookback_duration      = "P1D"
      entity_matching_method = "Selected"
      by_entities            = ["IP"]
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "User"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "HostName"
    }
  }

  custom_details = {
    FailedCount = "FailedCount"
    FirstFail   = "FirstFail"
  }

  depends_on = [azurerm_sentinel_watchlist.trusted_ips]
}

resource "azurerm_sentinel_alert_rule_scheduled" "r4_sudo_probing" {
  name                       = "r4-sudo-probing"
  display_name               = "R4 Sudo probing"
  description                = "sudo refused a user that is not in sudoers."
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  severity                   = "Medium"
  query                      = <<-KQL
    // R4 Sudo probing (T1548.003)
    // sudo refused a user that is not in sudoers, in the last 10 minutes. Only the
    // admin account is in sudoers, so this is the decoy account (or another
    // non-admin login) trying privilege escalation. sudo writes this to the auth
    // log, so no auditd parsing is needed. Medium incident (P2).
    // Example: "decoy : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/decoy ; USER=root ; COMMAND=/usr/bin/id"
    // The source IP comes from the user's latest SSH login in the last 24 hours.
    let Trusted = _GetWatchlist('Trusted_IPs') | project SearchKey;
    let Logins = Syslog
        | where TimeGenerated > ago(1d)
        | where Facility in ("auth", "authpriv") and ProcessName in ("sshd", "sshd-session")
        | where SyslogMessage startswith "Accepted "
        | extend User = extract(@"^Accepted \S+ for (\S+) from", 1, SyslogMessage),
                 SourceIP = extract(@" from (\d{1,3}(?:\.\d{1,3}){3}) ", 1, SyslogMessage)
        | summarize arg_max(TimeGenerated, SourceIP) by User, Computer
        | project User, Computer, SourceIP;
    Syslog
    | where TimeGenerated > ago(10m)
    | where Facility in ("auth", "authpriv") and ProcessName == "sudo"
    | where SyslogMessage has "NOT in sudoers"
    | extend User = extract(@"^\s*(\S+) : ", 1, SyslogMessage),
             Command = extract(@"COMMAND=(.*)$", 1, SyslogMessage)
    | join kind=leftouter Logins on User, Computer
    | where isempty(SourceIP) or SourceIP !in (Trusted)
    | project TimeGenerated, User, HostName = Computer, SourceIP, Command
  KQL
  query_frequency            = "PT10M"
  query_period               = "P1D"
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1548"]

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  # Repeated sudo attempts by the same account within a day go into one incident.
  incident {
    create_incident_enabled = true
    grouping {
      enabled                = true
      lookback_duration      = "P1D"
      entity_matching_method = "Selected"
      by_entities            = ["Account"]
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "User"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "HostName"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }

  custom_details = {
    Command = "Command"
  }

  depends_on = [azurerm_sentinel_watchlist.trusted_ips]
}

resource "azurerm_sentinel_alert_rule_scheduled" "r5_sustained_brute_force" {
  name                       = "r5-sustained-brute-force"
  display_name               = "R5 Sustained brute force"
  description                = "50 or more failed SSH logins from one IP in 10 minutes and no successful login from it in the last 24 hours."
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  severity                   = "Low"
  query                      = <<-KQL
    // R5 Sustained brute force (T1110.001, T1110.003)
    // 50 or more failed SSH logins from one IP in 10 minutes, and no successful
    // login from that IP in the last 24 hours. Low incident (P3), reviewed daily.
    let Trusted = _GetWatchlist('Trusted_IPs') | project SearchKey;
    let SshAuth = Syslog
        | where TimeGenerated > ago(1d)
        | where Facility in ("auth", "authpriv") and ProcessName in ("sshd", "sshd-session")
        | extend SourceIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage)
        | where isnotempty(SourceIP) and SourceIP !in (Trusted);
    let LoggedIn = SshAuth
        | where SyslogMessage startswith "Accepted "
        | distinct SourceIP;
    SshAuth
    | where TimeGenerated > ago(10m)
    | where SyslogMessage has_any ("Failed password", "Invalid user", "Connection closed by authenticating user")
    | extend User = extract(@"(?:Failed password for (?:invalid user )?|Invalid user |authenticating user )(\S+)", 1, SyslogMessage)
    | where SourceIP !in (LoggedIn)
    | summarize FailedCount = count(), DistinctUsers = dcount(User) by SourceIP, HostName = Computer
    | where FailedCount >= 50
  KQL
  query_frequency            = "PT10M"
  query_period               = "P1D"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  # A long attack from one IP stays one incident instead of one every 10 minutes.
  incident {
    create_incident_enabled = true
    grouping {
      enabled                = true
      lookback_duration      = "P1D"
      entity_matching_method = "Selected"
      by_entities            = ["IP"]
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "HostName"
    }
  }

  custom_details = {
    FailedCount   = "FailedCount"
    DistinctUsers = "DistinctUsers"
  }

  depends_on = [azurerm_sentinel_watchlist.trusted_ips]
}
