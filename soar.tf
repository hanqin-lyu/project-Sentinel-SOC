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

  # Each playbook is one job and is run by the analyst from the incident page.
  playbooks = {
    # PB8: post the incident facts as a comment to start the triage report.
    # IPs are defanged, as in the triage reports.
    pb8_report_draft = {
      name = "pb8-report-draft"
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

    # PB9: close the incident. A manual run cannot ask for input, so the
    # classification is fixed: activity on a honeypot is expected.
    pb9_close_incident = {
      name = "pb9-close-incident"
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
    parameters = {
      "$connections" = {
        type         = "Object"
        defaultValue = {}
      }
    }
    triggers = {
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
    actions = each.value.actions
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

# Comment on and close incidents, and nothing else.
resource "azurerm_role_assignment" "playbook_sentinel_responder" {
  for_each = local.playbooks

  scope                = data.azurerm_resource_group.sentinel.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = module.playbook[each.key].resource.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}
