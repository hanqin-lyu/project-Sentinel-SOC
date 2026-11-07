resource "azurerm_virtual_network" "honeypot" {
  name                = "vnet-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  address_space       = var.vnet_address_space
  tags                = local.tags
}

resource "azurerm_subnet" "honeypot" {
  name                 = "snet-honeypot"
  resource_group_name  = azurerm_resource_group.honeypot.name
  virtual_network_name = azurerm_virtual_network.honeypot.name
  address_prefixes     = [var.subnet_address_prefix]
}

resource "azurerm_network_security_group" "honeypot" {
  name                = "nsg-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "honeypot" {
  subnet_id                 = azurerm_subnet.honeypot.id
  network_security_group_id = azurerm_network_security_group.honeypot.id
}

resource "azurerm_public_ip" "honeypot" {
  name                = "pip-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

# ---------------------------------------------------------------------------
# Inbound rules. Lower number = evaluated first.
#   100  admin SSH from your IP only (optional)
#   200  SOAR block list, managed by the playbook (Deny)
#   300  honeypot SSH from anywhere
# ---------------------------------------------------------------------------
resource "azurerm_network_security_rule" "allow_admin_ssh" {
  count                       = var.management_source_cidr == "" ? 0 : 1
  name                        = "Allow-Admin-SSH-From-Mgmt"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = tostring(var.admin_ssh_port)
  source_address_prefix       = var.management_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

# The playbook (PB2) rewrites source_address_prefixes at run time. Terraform creates the
# rule with a harmless placeholder (documentation range, TEST-NET-1) and then leaves the
# list alone, so a later apply never removes live blocks.
resource "azurerm_network_security_rule" "soar_block" {
  name                        = "SOAR-Block-Attackers"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefixes     = ["192.0.2.1"]
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name

  lifecycle {
    ignore_changes = [source_address_prefixes]
  }
}

resource "azurerm_network_security_rule" "allow_honeypot_ssh" {
  name                        = "Allow-Honeypot-SSH-Any"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

# ---------------------------------------------------------------------------
# Outbound rules. The default AllowInternetOutBound rule (65001) is overridden by an
# explicit Internet deny at 4000, created only when lockdown_egress = true.
# ---------------------------------------------------------------------------
resource "azurerm_network_security_rule" "allow_azure_monitor_out" {
  name                        = "Allow-AzureMonitor-Out"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureMonitor"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

# Platform DNS / WireServer (168.63.129.16) and instance metadata (169.254.169.254):
# needed by the VM agent, name resolution and the managed identity the agent uses.
resource "azurerm_network_security_rule" "allow_platform_dns_out" {
  name                        = "Allow-AzurePlatformDNS-Out"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzurePlatformDNS"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "allow_platform_imds_out" {
  name                        = "Allow-AzurePlatformIMDS-Out"
  priority                    = 120
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzurePlatformIMDS"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "deny_internet_out" {
  count                       = var.lockdown_egress ? 1 : 0
  name                        = "Deny-Internet-Out"
  priority                    = 4000
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name

  # If both happen in one apply, lock down only after the agent and the collection
  # association exist. cloud-init finishes asynchronously, so the two-stage apply in the
  # README is still the safe path.
  depends_on = [
    azurerm_virtual_machine_extension.ama,
    azurerm_monitor_data_collection_rule_association.syslog,
  ]
}
