resource "azurerm_virtual_network" "honeypot" {
  name                = "vnet-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
  address_space       = ["10.10.0.0/16"]
}

resource "azurerm_subnet" "honeypot" {
  name                 = "snet-honeypot"
  resource_group_name  = azurerm_resource_group.honeypot.name
  virtual_network_name = azurerm_virtual_network.honeypot.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_network_security_group" "honeypot" {
  name                = "nsg-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name
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
}

# ---------------------------------------------------------------------------
# Inbound rules (lower number is checked first)
#   100  admin SSH on port 2222, from your IP only
#   200  block list, edited by the playbook
#   300  port 22 open to everyone: this is the honeypot
# ---------------------------------------------------------------------------
resource "azurerm_network_security_rule" "allow_admin_ssh" {
  count                       = var.management_source_cidr == "" ? 0 : 1
  name                        = "Allow-Admin-SSH-From-Mgmt"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "2222"
  source_address_prefix       = var.management_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.honeypot.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

# The playbook rewrites the address list. Terraform only creates the rule with a
# dummy address (192.0.2.1 is a documentation range) and then ignores the list,
# so a later apply never wipes real blocks.
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
# Outbound rules: only Azure Monitor and Azure's own services may be reached.
# The "deny all Internet" rule exists only when lockdown_egress = true.
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
}
