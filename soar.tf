# Logic Apps playbooks and their API connections go in this resource group.
# Created by hand, so the pipeline needs no subscription-level write access.
data "azurerm_resource_group" "automation" {
  name = "rg-core-automation"
}

data "azurerm_client_config" "current" {}

# Lets automation rules and the Run playbook button start playbooks here, and
# nothing else. The principal is Sentinel's own service account in this tenant.
resource "azurerm_role_assignment" "sentinel_runs_playbooks" {
  scope                = data.azurerm_resource_group.automation.id
  role_definition_name = "Microsoft Sentinel Automation Contributor"
  principal_id         = var.sentinel_automation_principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------------------------------------------------------------------
# Key Vault for playbook secrets
# ---------------------------------------------------------------------------
# Holds the third-party secrets the playbooks need (the AbuseIPDB API key now,
# the Slack webhook URL later). Terraform creates the vault empty and grants each
# playbook identity read access; the secret VALUES are set by hand with
# `az keyvault secret set`, so no secret is ever in the repo or the state. RBAC
# authorization is the module default here, so there are no access policies.
module "key_vault" {
  source  = "Azure/avm-res-keyvault-vault/azurerm"
  version = "0.13.1"

  # Key Vault names are globally unique, so a short hash of the resource group
  # keeps the name stable and collision-free without hard-coding a guess.
  name             = "kv-socsoar-${substr(sha1(data.azurerm_resource_group.automation.id), 0, 6)}"
  location         = local.location
  parent_id        = data.azurerm_resource_group.automation.id
  tenant_id        = data.azurerm_client_config.current.tenant_id
  sku_name         = "standard"
  enable_telemetry = false

  # Lab vault: no firewall, so the Consumption Logic App managed identity reaches
  # it over the public endpoint. Soft delete is mandatory in Azure and cannot be
  # turned off, so set the shortest retention explicitly (the module would
  # otherwise send enableSoftDelete = false and the apply would fail). Purge
  # protection stays off, so a deleted vault can be purged instead of lingering.
  network_acls               = null
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}

locals {
  sentinel_managed_api_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Web/locations/${local.location}/managedApis/azuresentinel"

  # Fields every incident-triggered playbook reads.
  incident_id    = "@triggerBody()?['object']?['id']"
  incident_props = "triggerBody()?['object']?['properties']"

  sentinel_host = {
    connection = {
      name = "@parameters('$connections')['azuresentinel']['connectionId']"
    }
  }

  # Started by an automation rule or by Run playbook on the incident page.
  sentinel_incident_trigger = {
    Microsoft_Sentinel_incident = {
      type = "ApiConnectionWebhook"
      inputs = {
        host = local.sentinel_host
        body = {
          callback_url = "@{listCallbackUrl()}"
        }
        path = "/incident-creation"
      }
    }
  }

  # PB5 and PB6 call Azure APIs directly with the HTTP action and their own
  # managed identity, so they need no extra API connection.
  #   NSG rule        Azure Resource Manager (Network Contributor on the rule)
  #   log query       Log Analytics query API (Sentinel Responder can query)
  #   SOARBlocks_CL   Logs Ingestion API (Monitoring Metrics Publisher on the DCR)
  block_rule_url = "https://management.azure.com${azurerm_network_security_rule.soar_block.id}?api-version=2024-05-01"
  arm_auth       = { type = "ManagedServiceIdentity", audience = "https://management.azure.com/" }
  # The query API takes the workspace GUID. The module output is sensitive only
  # because it also holds the workspace keys.
  log_query_url  = "https://api.loganalytics.io/v1/workspaces/${nonsensitive(module.workspace.resource.workspace_id)}/query"
  log_query_auth = { type = "ManagedServiceIdentity", audience = "https://api.loganalytics.io" }
  block_log_url  = "${module.dce_soar.logs_ingestion_endpoint}/dataCollectionRules/${module.dcr_soar_blocks.resource.output.properties.immutableId}/streams/Custom-SOARBlocks_CL?api-version=2023-01-01"
  block_log_auth = { type = "ManagedServiceIdentity", audience = "https://monitor.azure.com" }

  # The notify playbooks (PB2, PB3, PB4) read the Slack incoming-webhook URL from
  # Key Vault with the managed identity and POST the alert to it. The webhook URL
  # is itself the secret, so the fetch hides its output and the POST hides its
  # input. Slack incoming webhooks cannot attach a file, so the P2 and P3
  # messages link to the SLA doc in the repo instead of attaching it.
  kv_auth              = { type = "ManagedServiceIdentity", audience = "https://vault.azure.net" }
  slack_webhook_kv_url = "https://${module.key_vault.name}.vault.azure.net/secrets/slack-webhook-url?api-version=7.4"
  sla_doc_base         = "https://github.com/hanqin-lyu/project-Sentinel-SOC/blob/main/docs/sla"

  # Each playbook is one job (README, Playbooks).
  playbooks = {
    # PB1 (automatic, AR-R4 and AR-R5): look up the attacker IP in AbuseIPDB and
    # write the reputation as an incident comment. The API key is read from Key
    # Vault at run time with the managed identity; it never appears in the
    # definition or the run history (secureData hides the key fetch and the call).
    pb1_enrichment = {
      name       = "pb1-enrichment"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        IP_entities = {
          type     = "Query"
          runAfter = {}
          inputs = {
            from  = "@${local.incident_props}?['relatedEntities']"
            where = "@equals(item()?['kind'], 'Ip')"
          }
        }
        IP_addresses = {
          type     = "Select"
          runAfter = { IP_entities = ["Succeeded"] }
          inputs = {
            from   = "@body('IP_entities')"
            select = "@item()?['properties']?['address']"
          }
        }
        # R4 and R5 group their alerts by IP, so an incident has one. Quotes are
        # removed because the value goes into a URL query.
        IP = {
          type     = "Compose"
          runAfter = { IP_addresses = ["Succeeded"] }
          inputs   = "@{replace(join(take(body('IP_addresses'), 1), ''), '''', '')}"
        }
        # Read the AbuseIPDB key from Key Vault with the managed identity. The
        # output holds the secret, so it is kept out of the run history.
        Get_api_key = {
          type                 = "Http"
          runAfter             = { IP = ["Succeeded"] }
          runtimeConfiguration = { secureData = { properties = ["outputs"] } }
          inputs = {
            method         = "GET"
            uri            = "https://${module.key_vault.name}.vault.azure.net/secrets/abuseipdb-api-key?api-version=7.4"
            authentication = { type = "ManagedServiceIdentity", audience = "https://vault.azure.net" }
          }
        }
        # The Key header carries the secret, so these inputs are hidden too.
        Check_AbuseIPDB = {
          type                 = "Http"
          runAfter             = { Get_api_key = ["Succeeded"] }
          runtimeConfiguration = { secureData = { properties = ["inputs"] } }
          inputs = {
            method  = "GET"
            uri     = "https://api.abuseipdb.com/api/v2/check"
            queries = { ipAddress = "@outputs('IP')", maxAgeInDays = "90" }
            headers = {
              Key    = "@body('Get_api_key')?['value']"
              Accept = "application/json"
            }
          }
        }
        Comment_enrichment = {
          type     = "ApiConnection"
          runAfter = { Check_AbuseIPDB = ["Succeeded"] }
          inputs = {
            host   = local.sentinel_host
            method = "post"
            path   = "/Incidents/Comment"
            body = {
              incidentArmId = local.incident_id
              message       = <<-HTML
                <p><strong>Enrichment (PB1) &mdash; AbuseIPDB</strong></p>
                <p>IP: @{replace(outputs('IP'), '.', '[.]')}<br>
                Abuse confidence: @{body('Check_AbuseIPDB')?['data']?['abuseConfidenceScore']}%<br>
                Total reports: @{body('Check_AbuseIPDB')?['data']?['totalReports']}<br>
                Country: @{body('Check_AbuseIPDB')?['data']?['countryCode']}<br>
                ISP: @{body('Check_AbuseIPDB')?['data']?['isp']}<br>
                Usage type: @{body('Check_AbuseIPDB')?['data']?['usageType']}<br>
                Last reported (UTC): @{body('Check_AbuseIPDB')?['data']?['lastReportedAt']}</p>
              HTML
            }
          }
        }
      }
    }

    # PB2 (automatic, AR-R4): the P2 notifier for R4 Sudo probing. Comments the
    # acknowledge-by time (30 minutes from creation) and posts the alert to Slack
    # with a link to the P2 SLA. The Slack webhook URL is read from Key Vault at
    # run time and never shown in the run history. Priority is carried by the
    # incident severity, the comment and the Slack message, not an incident label
    # (see README design notes: Defender-integrated incidents do not hold them).
    pb2_notify_p2 = {
      name       = "pb2-notify-p2"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        IP_entities = {
          type     = "Query"
          runAfter = {}
          inputs = {
            from  = "@${local.incident_props}?['relatedEntities']"
            where = "@equals(item()?['kind'], 'Ip')"
          }
        }
        IP_addresses = {
          type     = "Select"
          runAfter = { IP_entities = ["Succeeded"] }
          inputs = {
            from   = "@body('IP_entities')"
            select = "@item()?['properties']?['address']"
          }
        }
        IP = {
          type     = "Compose"
          runAfter = { IP_addresses = ["Succeeded"] }
          inputs   = "@{replace(join(take(body('IP_addresses'), 1), ''), '''', '')}"
        }
        # P2 acknowledge target: 30 minutes after the incident was created.
        Due_time = {
          type     = "Compose"
          runAfter = {}
          inputs   = "@{addMinutes(${local.incident_props}?['createdTimeUtc'], 30)}"
        }
        Comment_due = {
          type     = "ApiConnection"
          runAfter = { Due_time = ["Succeeded"] }
          inputs = {
            host   = local.sentinel_host
            method = "post"
            path   = "/Incidents/Comment"
            body = {
              incidentArmId = local.incident_id
              message       = "<p><strong>Priority P2 (PB2).</strong> Acknowledge by @{outputs('Due_time')} (UTC, 30 min from creation); resolve same day. SLA: docs/sla/P2-sla.md.</p>"
            }
          }
        }
        Get_webhook = {
          type                 = "Http"
          runAfter             = {}
          runtimeConfiguration = { secureData = { properties = ["outputs"] } }
          inputs = {
            method         = "GET"
            uri            = local.slack_webhook_kv_url
            authentication = local.kv_auth
          }
        }
        # The URI is the webhook secret, so the inputs are hidden.
        Send_slack = {
          type                 = "Http"
          runAfter             = { IP = ["Succeeded"], Due_time = ["Succeeded"], Get_webhook = ["Succeeded"] }
          runtimeConfiguration = { secureData = { properties = ["inputs"] } }
          inputs = {
            method = "POST"
            uri    = "@body('Get_webhook')?['value']"
            body = {
              text = "P2 incident: @{${local.incident_props}?['title']}"
              blocks = [
                {
                  type = "header"
                  text = { type = "plain_text", text = "🟠 P2 — Sudo probing (R4)", emoji = true }
                },
                {
                  type = "section"
                  text = {
                    type = "mrkdwn"
                    text = "*Incident:* #@{${local.incident_props}?['incidentNumber']} @{${local.incident_props}?['title']}\n*Severity:* @{${local.incident_props}?['severity']}\n*Source IP:* @{replace(outputs('IP'), '.', '[.]')}\n*Created (UTC):* @{${local.incident_props}?['createdTimeUtc']}\n*Acknowledge by (UTC):* @{outputs('Due_time')}"
                  }
                },
                {
                  type = "section"
                  text = { type = "mrkdwn", text = "<${local.sla_doc_base}/P2-sla.md|P2 response SLA>" }
                }
              ]
            }
          }
        }
      }
    }

    # PB3 (automatic, AR-R5): the P3 notifier for R5 Sustained brute force.
    # Comments the acknowledge target and posts the alert to Slack with a link to
    # the P3 SLA. P3 has no clock deadline (it is handled at the next daily
    # review), so the comment states that target as text. Priority is carried by
    # severity, the comment and Slack, not an incident label (see PB2).
    pb3_notify_p3 = {
      name       = "pb3-notify-p3"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        IP_entities = {
          type     = "Query"
          runAfter = {}
          inputs = {
            from  = "@${local.incident_props}?['relatedEntities']"
            where = "@equals(item()?['kind'], 'Ip')"
          }
        }
        IP_addresses = {
          type     = "Select"
          runAfter = { IP_entities = ["Succeeded"] }
          inputs = {
            from   = "@body('IP_entities')"
            select = "@item()?['properties']?['address']"
          }
        }
        IP = {
          type     = "Compose"
          runAfter = { IP_addresses = ["Succeeded"] }
          inputs   = "@{replace(join(take(body('IP_addresses'), 1), ''), '''', '')}"
        }
        Comment_due = {
          type     = "ApiConnection"
          runAfter = {}
          inputs = {
            host   = local.sentinel_host
            method = "post"
            path   = "/Incidents/Comment"
            body = {
              incidentArmId = local.incident_id
              message       = "<p><strong>Priority P3 (PB3).</strong> Acknowledge at the next daily review; resolve same day. SLA: docs/sla/P3-sla.md.</p>"
            }
          }
        }
        Get_webhook = {
          type                 = "Http"
          runAfter             = {}
          runtimeConfiguration = { secureData = { properties = ["outputs"] } }
          inputs = {
            method         = "GET"
            uri            = local.slack_webhook_kv_url
            authentication = local.kv_auth
          }
        }
        Send_slack = {
          type                 = "Http"
          runAfter             = { IP = ["Succeeded"], Get_webhook = ["Succeeded"] }
          runtimeConfiguration = { secureData = { properties = ["inputs"] } }
          inputs = {
            method = "POST"
            uri    = "@body('Get_webhook')?['value']"
            body = {
              text = "P3 incident: @{${local.incident_props}?['title']}"
              blocks = [
                {
                  type = "header"
                  text = { type = "plain_text", text = "🟡 P3 — Sustained brute force (R5)", emoji = true }
                },
                {
                  type = "section"
                  text = {
                    type = "mrkdwn"
                    text = "*Incident:* #@{${local.incident_props}?['incidentNumber']} @{${local.incident_props}?['title']}\n*Severity:* @{${local.incident_props}?['severity']}\n*Source IP:* @{replace(outputs('IP'), '.', '[.]')}\n*Created (UTC):* @{${local.incident_props}?['createdTimeUtc']}\n*Acknowledge:* next daily review"
                  }
                },
                {
                  type = "section"
                  text = { type = "mrkdwn", text = "<${local.sla_doc_base}/P3-sla.md|P3 response SLA>" }
                }
              ]
            }
          }
        }
      }
    }

    # PB4 (automatic, AR-R2): the P1 notifier for R2 Compromise after brute
    # force. Posts the alert to Slack. PB5 blocks the IP on the same incident, so
    # this is notification only; there is no SLA doc for P1 (act now). Priority is
    # carried by severity and the Slack message, not an incident label (see PB2).
    pb4_notify_p1 = {
      name       = "pb4-notify-p1"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        IP_entities = {
          type     = "Query"
          runAfter = {}
          inputs = {
            from  = "@${local.incident_props}?['relatedEntities']"
            where = "@equals(item()?['kind'], 'Ip')"
          }
        }
        IP_addresses = {
          type     = "Select"
          runAfter = { IP_entities = ["Succeeded"] }
          inputs = {
            from   = "@body('IP_entities')"
            select = "@item()?['properties']?['address']"
          }
        }
        IP = {
          type     = "Compose"
          runAfter = { IP_addresses = ["Succeeded"] }
          inputs   = "@{replace(join(take(body('IP_addresses'), 1), ''), '''', '')}"
        }
        Get_webhook = {
          type                 = "Http"
          runAfter             = {}
          runtimeConfiguration = { secureData = { properties = ["outputs"] } }
          inputs = {
            method         = "GET"
            uri            = local.slack_webhook_kv_url
            authentication = local.kv_auth
          }
        }
        Send_slack = {
          type                 = "Http"
          runAfter             = { IP = ["Succeeded"], Get_webhook = ["Succeeded"] }
          runtimeConfiguration = { secureData = { properties = ["inputs"] } }
          inputs = {
            method = "POST"
            uri    = "@body('Get_webhook')?['value']"
            body = {
              text = "P1 incident: @{${local.incident_props}?['title']}"
              blocks = [
                {
                  type = "header"
                  text = { type = "plain_text", text = "🔴 P1 — Compromise after brute force (R2)", emoji = true }
                },
                {
                  type = "section"
                  text = {
                    type = "mrkdwn"
                    text = "*Incident:* #@{${local.incident_props}?['incidentNumber']} @{${local.incident_props}?['title']}\n*Severity:* @{${local.incident_props}?['severity']}\n*Source IP:* @{replace(outputs('IP'), '.', '[.]')}\n*Created (UTC):* @{${local.incident_props}?['createdTimeUtc']}\n*Action:* PB5 is blocking this IP now. Acknowledge immediately."
                  }
                }
              ]
            }
          }
        }
      }
    }

    # PB5 (automatic, AR-R2): add the attacker IP to SOAR-Block-Attackers and
    # log the block with its expiry in SOARBlocks_CL. Skips with a comment when
    # the kill switch is off, or the IP is invalid, private, trusted or already
    # blocked. An IP that is still blocked keeps its first expiry.
    pb5_block_ip = {
      name     = "pb5-block-ip"
      triggers = local.sentinel_incident_trigger
      parameters = {
        blockEnabled  = { type = "Bool", defaultValue = true }
        blockTtlHours = { type = "Int", defaultValue = 24 }
      }
      actions = {
        IP_entities = {
          type     = "Query"
          runAfter = {}
          inputs = {
            from  = "@${local.incident_props}?['relatedEntities']"
            where = "@equals(item()?['kind'], 'Ip')"
          }
        }
        IP_addresses = {
          type     = "Select"
          runAfter = { IP_entities = ["Succeeded"] }
          inputs = {
            from   = "@body('IP_entities')"
            select = "@item()?['properties']?['address']"
          }
        }
        # R2 groups its alerts by IP, so an incident has one. Quotes are removed
        # because the value goes into a KQL string.
        IP = {
          type     = "Compose"
          runAfter = { IP_addresses = ["Succeeded"] }
          inputs   = "@{replace(join(take(body('IP_addresses'), 1), ''), '''', '')}"
        }
        # One row: [Valid, Private, Trusted].
        Check_IP = {
          type     = "Http"
          runAfter = { IP = ["Succeeded"] }
          inputs = {
            method         = "POST"
            uri            = local.log_query_url
            authentication = local.log_query_auth
            body = {
              query = <<-KQL
                let ip = '@{outputs('IP')}';
                let trusted = toscalar(_GetWatchlist('Trusted_IPs') | where SearchKey == ip | count) > 0;
                print Valid = isnotnull(parse_ipv4(ip)), Private = coalesce(ipv4_is_private(ip), false), Trusted = trusted
              KQL
            }
          }
        }
        Get_block_rule = {
          type     = "Http"
          runAfter = { IP = ["Succeeded"] }
          inputs = {
            method         = "GET"
            uri            = local.block_rule_url
            authentication = local.arm_auth
          }
        }
        # Empty means block.
        Skip_reason = {
          type     = "Compose"
          runAfter = { Check_IP = ["Succeeded"], Get_block_rule = ["Succeeded"] }
          inputs   = "@{if(not(parameters('blockEnabled')), 'the kill switch blockEnabled is off', if(not(body('Check_IP')?['tables'][0]['rows'][0][0]), 'no valid IPv4 address on the incident', if(body('Check_IP')?['tables'][0]['rows'][0][1], 'private address', if(body('Check_IP')?['tables'][0]['rows'][0][2], 'trusted address (Trusted_IPs)', if(contains(body('Get_block_rule')?['properties']?['sourceAddressPrefixes'], outputs('IP')), 'already blocked', '')))))}"
        }
        Block_or_skip = {
          type     = "If"
          runAfter = { Skip_reason = ["Succeeded"] }
          expression = {
            and = [{ equals = ["@outputs('Skip_reason')", ""] }]
          }
          actions = {
            Expires_at = {
              type     = "Compose"
              runAfter = {}
              inputs   = "@{addHours(utcNow(), parameters('blockTtlHours'))}"
            }
            # The PUT returns before the rule is provisioned. Waiting would poll
            # an operation URL outside the rule's scope, which the identity has
            # no role on.
            Update_block_rule = {
              type             = "Http"
              runAfter         = { Expires_at = ["Succeeded"] }
              operationOptions = "DisableAsyncPattern"
              inputs = {
                method         = "PUT"
                uri            = local.block_rule_url
                authentication = local.arm_auth
                body = {
                  properties = "@setProperty(body('Get_block_rule')?['properties'], 'sourceAddressPrefixes', union(body('Get_block_rule')?['properties']?['sourceAddressPrefixes'], createArray(outputs('IP'))))"
                }
              }
            }
            Log_block = {
              type     = "Http"
              runAfter = { Update_block_rule = ["Succeeded"] }
              inputs = {
                method         = "POST"
                uri            = local.block_log_url
                authentication = local.block_log_auth
                body = [{
                  TimeGenerated = "@{utcNow()}"
                  IPAddress     = "@{outputs('IP')}"
                  Action        = "Block"
                  ExpiresAt     = "@{outputs('Expires_at')}"
                  IncidentArmId = local.incident_id
                  Playbook      = "pb5-block-ip"
                }]
              }
            }
            Comment_blocked = {
              type     = "ApiConnection"
              runAfter = { Log_block = ["Succeeded"] }
              inputs = {
                host   = local.sentinel_host
                method = "post"
                path   = "/Incidents/Comment"
                body = {
                  incidentArmId = local.incident_id
                  message       = "<p><strong>Blocked by PB5.</strong> @{replace(outputs('IP'), '.', '[.]')} is in SOAR-Block-Attackers until @{outputs('Expires_at')} (UTC, TTL @{parameters('blockTtlHours')} h). PB6 removes it after that.</p>"
                }
              }
            }
          }
          else = {
            actions = {
              Comment_skipped = {
                type     = "ApiConnection"
                runAfter = {}
                inputs = {
                  host   = local.sentinel_host
                  method = "post"
                  path   = "/Incidents/Comment"
                  body = {
                    incidentArmId = local.incident_id
                    message       = "<p><strong>PB5 did not block</strong> @{replace(outputs('IP'), '.', '[.]')}: @{outputs('Skip_reason')}.</p>"
                  }
                }
              }
            }
          }
        }
      }
    }

    # PB6 (automatic, every hour): find blocks past their expiry in
    # SOARBlocks_CL, remove those IPs from the rule in one update, log an
    # Unblock row for each and comment on the incident that blocked it.
    # The 192.0.2.1 placeholder is never in the table, so the rule never ends
    # up with an empty address list.
    pb6_block_expiry = {
      name = "pb6-block-expiry"
      triggers = {
        Every_hour = {
          type       = "Recurrence"
          recurrence = { frequency = "Hour", interval = 1 }
        }
      }
      parameters = {}
      actions = {
        # Rows: [IPAddress, IncidentArmId].
        Find_expired = {
          type     = "Http"
          runAfter = {}
          inputs = {
            method         = "POST"
            uri            = local.log_query_url
            authentication = local.log_query_auth
            body = {
              query = <<-KQL
                SOARBlocks_CL
                | where TimeGenerated > ago(30d)
                | summarize arg_max(TimeGenerated, Action, ExpiresAt, IncidentArmId) by IPAddress
                | where Action == "Block" and ExpiresAt < now()
                | project IPAddress, IncidentArmId
              KQL
            }
          }
        }
        Expired = {
          type     = "Compose"
          runAfter = { Find_expired = ["Succeeded"] }
          inputs   = "@body('Find_expired')?['tables'][0]['rows']"
        }
        Any_expired = {
          type     = "If"
          runAfter = { Expired = ["Succeeded"] }
          expression = {
            and = [{ greater = ["@length(outputs('Expired'))", 0] }]
          }
          actions = {
            Expired_IPs = {
              type     = "Select"
              runAfter = {}
              inputs = {
                from   = "@outputs('Expired')"
                select = "@item()[0]"
              }
            }
            Get_block_rule = {
              type     = "Http"
              runAfter = { Expired_IPs = ["Succeeded"] }
              inputs = {
                method         = "GET"
                uri            = local.block_rule_url
                authentication = local.arm_auth
              }
            }
            Kept_prefixes = {
              type     = "Query"
              runAfter = { Get_block_rule = ["Succeeded"] }
              inputs = {
                from  = "@body('Get_block_rule')?['properties']?['sourceAddressPrefixes']"
                where = "@not(contains(body('Expired_IPs'), item()))"
              }
            }
            # See PB5 for why the async pattern is off.
            Update_block_rule = {
              type             = "Http"
              runAfter         = { Kept_prefixes = ["Succeeded"] }
              operationOptions = "DisableAsyncPattern"
              inputs = {
                method         = "PUT"
                uri            = local.block_rule_url
                authentication = local.arm_auth
                body = {
                  properties = "@setProperty(body('Get_block_rule')?['properties'], 'sourceAddressPrefixes', body('Kept_prefixes'))"
                }
              }
            }
            Unblock_rows = {
              type     = "Select"
              runAfter = { Update_block_rule = ["Succeeded"] }
              inputs = {
                from = "@outputs('Expired')"
                select = {
                  TimeGenerated = "@{utcNow()}"
                  IPAddress     = "@{item()[0]}"
                  Action        = "Unblock"
                  IncidentArmId = "@{item()[1]}"
                  Playbook      = "pb6-block-expiry"
                }
              }
            }
            Log_unblocks = {
              type     = "Http"
              runAfter = { Unblock_rows = ["Succeeded"] }
              inputs = {
                method         = "POST"
                uri            = local.block_log_url
                authentication = local.block_log_auth
                body           = "@body('Unblock_rows')"
              }
            }
            Comment_each_incident = {
              type     = "Foreach"
              runAfter = { Log_unblocks = ["Succeeded"] }
              foreach  = "@outputs('Expired')"
              actions = {
                Comment_unblocked = {
                  type     = "ApiConnection"
                  runAfter = {}
                  inputs = {
                    host   = local.sentinel_host
                    method = "post"
                    path   = "/Incidents/Comment"
                    body = {
                      incidentArmId = "@{items('Comment_each_incident')[1]}"
                      message       = "<p><strong>Unblocked by PB6.</strong> @{replace(items('Comment_each_incident')[0], '.', '[.]')} is removed from SOAR-Block-Attackers: TTL reached.</p>"
                    }
                  }
                }
              }
            }
          }
          else = {
            actions = {}
          }
        }
      }
    }

    # PB8 (manual): post the incident facts as a comment to start the triage
    # report. IPs are defanged, as in the triage reports.
    pb8_report_draft = {
      name       = "pb8-report-draft"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        Entity_names = {
          type     = "Select"
          runAfter = {}
          inputs = {
            from   = "@${local.incident_props}?['relatedEntities']"
            select = "@item()?['properties']?['friendlyName']"
          }
        }
        Add_comment = {
          type     = "ApiConnection"
          runAfter = { Entity_names = ["Succeeded"] }
          inputs = {
            host   = local.sentinel_host
            method = "post"
            path   = "/Incidents/Comment"
            body = {
              incidentArmId = local.incident_id
              message       = <<-HTML
                <p><strong>Report draft (PB8)</strong></p>
                <p>Incident: @{${local.incident_props}?['incidentNumber']} @{${local.incident_props}?['title']}<br>
                Severity: @{${local.incident_props}?['severity']}<br>
                Created (UTC): @{${local.incident_props}?['createdTimeUtc']}<br>
                First activity (UTC): @{${local.incident_props}?['firstActivityTimeUtc']}<br>
                Last activity (UTC): @{${local.incident_props}?['lastActivityTimeUtc']}<br>
                Entities: @{replace(join(body('Entity_names'), ', '), '.', '[.]')}</p>
              HTML
            }
          }
        }
      }
    }

    # PB9 (manual): close the incident. A manual run cannot ask for input, so
    # the classification is fixed: activity on a honeypot is expected.
    pb9_close_incident = {
      name       = "pb9-close-incident"
      triggers   = local.sentinel_incident_trigger
      parameters = {}
      actions = {
        Add_comment = {
          type     = "ApiConnection"
          runAfter = {}
          inputs = {
            host   = local.sentinel_host
            method = "post"
            path   = "/Incidents/Comment"
            body = {
              incidentArmId = local.incident_id
              message       = "<p><strong>Closed by PB9.</strong> Reviewed by the analyst. Activity on the honeypot is expected.</p>"
            }
          }
        }
        Close_incident = {
          type     = "ApiConnection"
          runAfter = { Add_comment = ["Succeeded"] }
          inputs = {
            host   = local.sentinel_host
            method = "put"
            path   = "/Incidents"
            body = {
              incidentArmId = local.incident_id
              status        = "Closed"
              classification = {
                ClassificationAndReason  = "BenignPositive - SuspiciousButExpected"
                ClassificationReasonText = "Closed by PB9 after analyst review. Activity on the honeypot is expected."
              }
            }
          }
        }
      }
    }
  }
}

# Native azurerm_api_connection cannot set parameterValueType, which a managed
# identity connection needs, so this one uses azapi.
resource "azapi_resource" "sentinel_connection" {
  type      = "Microsoft.Web/connections@2016-06-01"
  name      = "azuresentinel"
  parent_id = data.azurerm_resource_group.automation.id
  location  = local.location

  # kind and parameterValueType are not in the provider's schema for this type.
  schema_validation_enabled = false

  body = {
    kind = "V1"
    properties = {
      displayName        = "azuresentinel"
      parameterValueType = "Alternative"
      api = {
        id = local.sentinel_managed_api_id
      }
    }
  }
}

module "playbook" {
  source   = "Azure/avm-res-logic-workflow/azurerm"
  version  = "0.2.0"
  for_each = local.playbooks

  name                = each.value.name
  location            = local.location
  resource_group_id   = data.azurerm_resource_group.automation.id
  resource_group_name = data.azurerm_resource_group.automation.name
  enable_telemetry    = false

  managed_identities = {
    system_assigned = true
  }

  logic_app_definition = {
    "$schema"      = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
    contentVersion = "1.0.0.0"
    outputs        = {}
    # Settings such as the kill switch and the block TTL are parameters, so
    # behaviour changes without copying a playbook.
    parameters = merge({
      "$connections" = {
        type         = "Object"
        defaultValue = {}
      }
    }, each.value.parameters)
    triggers = each.value.triggers
    actions  = each.value.actions
  }

  workflow_parameters = {
    "$connections" = {
      value = {
        azuresentinel = {
          connectionId   = azapi_resource.sentinel_connection.id
          connectionName = azapi_resource.sentinel_connection.name
          id             = local.sentinel_managed_api_id
          connectionProperties = {
            authentication = {
              type = "ManagedServiceIdentity"
            }
          }
        }
      }
    }
  }
}

# Comment on and close incidents, and query the workspace (PB5 checks
# Trusted_IPs, PB6 reads SOARBlocks_CL). Responder includes workspace query.
resource "azurerm_role_assignment" "playbook_sentinel_responder" {
  for_each = local.playbooks

  scope                = data.azurerm_resource_group.sentinel.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = module.playbook[each.key].resource.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

locals {
  block_playbooks = toset(["pb5_block_ip", "pb6_block_expiry"])
}

# Edit the SOAR-Block-Attackers rule, and no other rule or the NSG itself.
resource "azurerm_role_assignment" "playbook_block_rule" {
  for_each = local.block_playbooks

  scope                = azurerm_network_security_rule.soar_block.id
  role_definition_name = "Network Contributor"
  principal_id         = module.playbook[each.key].resource.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

# Write rows to SOARBlocks_CL through this one DCR.
resource "azurerm_role_assignment" "playbook_block_log" {
  for_each = local.block_playbooks

  scope                = module.dcr_soar_blocks.resource_id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = module.playbook[each.key].resource.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

locals {
  # Playbooks that read a secret from the Key Vault. PB10 joins here when it is
  # built (the Slack webhook URL). PB1 reads the AbuseIPDB key; PB2, PB3 and PB4
  # read the Slack webhook URL.
  keyvault_playbooks = toset(["pb1_enrichment", "pb2_notify_p2", "pb3_notify_p3", "pb4_notify_p1"])
}

# Read secrets from the playbook Key Vault, and nothing else on it.
resource "azurerm_role_assignment" "playbook_keyvault_reader" {
  for_each = local.keyvault_playbooks

  scope                = module.key_vault.resource_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.playbook[each.key].resource.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------------------------------------------------------------------
# Automation rules
# ---------------------------------------------------------------------------
# One per analytics rule. They only start playbooks and change nothing on the
# incident. The name must be a GUID; it is fixed so the rule keeps its ID.

# AR-R2: R2 Compromise after brute force (P1). Runs PB1 Enrichment, PB5 Block IP
# and PB4 Notify P1.
resource "azurerm_sentinel_automation_rule" "ar_r2" {
  name                       = "bdf3ec36-f3d8-4043-a424-ed61c66869c2"
  display_name               = "AR-R2 Compromise after brute force"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentRelatedAnalyticRuleIds"
      operator       = "Contains"
      propertyValues = [azurerm_sentinel_alert_rule_scheduled.r2_compromise_after_brute_force.id]
    }
  }])

  action_playbook {
    order        = 1
    logic_app_id = module.playbook["pb1_enrichment"].resource_id
  }

  action_playbook {
    order        = 2
    logic_app_id = module.playbook["pb5_block_ip"].resource_id
  }

  action_playbook {
    order        = 3
    logic_app_id = module.playbook["pb4_notify_p1"].resource_id
  }

  # Sentinel can start a playbook only once it has its role on the group.
  depends_on = [azurerm_role_assignment.sentinel_runs_playbooks]
}

# AR-R4: R4 Sudo probing (P2). Runs PB1 Enrichment and PB2 Notify P2.
resource "azurerm_sentinel_automation_rule" "ar_r4" {
  name                       = "c7a1e4b2-5d63-4f81-9a2c-3e6b8d1f0a47"
  display_name               = "AR-R4 Sudo probing"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  order                      = 2
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentRelatedAnalyticRuleIds"
      operator       = "Contains"
      propertyValues = [azurerm_sentinel_alert_rule_scheduled.r4_sudo_probing.id]
    }
  }])

  action_playbook {
    order        = 1
    logic_app_id = module.playbook["pb1_enrichment"].resource_id
  }

  action_playbook {
    order        = 2
    logic_app_id = module.playbook["pb2_notify_p2"].resource_id
  }

  depends_on = [azurerm_role_assignment.sentinel_runs_playbooks]
}

# AR-R5: R5 Sustained brute force (P3). Runs PB1 Enrichment and PB3 Notify P3.
resource "azurerm_sentinel_automation_rule" "ar_r5" {
  name                       = "e2f5b9a1-7c84-4d63-8b1e-5a9c2d4f6e38"
  display_name               = "AR-R5 Sustained brute force"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.soc.workspace_id
  order                      = 3
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentRelatedAnalyticRuleIds"
      operator       = "Contains"
      propertyValues = [azurerm_sentinel_alert_rule_scheduled.r5_sustained_brute_force.id]
    }
  }])

  action_playbook {
    order        = 1
    logic_app_id = module.playbook["pb1_enrichment"].resource_id
  }

  action_playbook {
    order        = 2
    logic_app_id = module.playbook["pb3_notify_p3"].resource_id
  }

  depends_on = [azurerm_role_assignment.sentinel_runs_playbooks]
}
