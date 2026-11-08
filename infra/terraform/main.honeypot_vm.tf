# The honeypot VM: Ubuntu 24.04 with a key-only admin account and auditd.

# Private IP from the subnet plus the public IP. No NSG here; the subnet NSG
# applies.
resource "azurerm_network_interface" "honeypot" {
  name                = "nic-honeypot"
  location            = azurerm_resource_group.honeypot.location
  resource_group_name = azurerm_resource_group.honeypot.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.honeypot.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.honeypot.id
  }
}

resource "azurerm_linux_virtual_machine" "honeypot" {
  name                  = "vm-honeypot-01"
  location              = azurerm_resource_group.honeypot.location
  resource_group_name   = azurerm_resource_group.honeypot.name
  size                  = "Standard_B2s"
  admin_username        = "azureops"
  network_interface_ids = [azurerm_network_interface.honeypot.id]

  # The admin account uses a key. The weak-password decoy account is created
  # inside the VM by hand later, never in Terraform.
  # This setting also turns off password login in sshd, so the decoy needs
  # password login switched back on for that account by hand.
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureops"
    public_key = var.admin_ssh_public_key
  }

  # Needed by the monitoring agent. No role is assigned to it on purpose, so a
  # hacked honeypot cannot call Azure APIs.
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  # Serial console access if SSH breaks. Uses a managed storage account.
  boot_diagnostics {}

  # Installs auditd and logs every command run by real login users.
  custom_data = base64encode(file("${path.module}/cloud-init.yaml"))
}
