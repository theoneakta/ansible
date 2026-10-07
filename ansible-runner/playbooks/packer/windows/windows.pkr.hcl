# Windows base image - Windows 11 Pro, Windows Server 2025, ... (one profile
# per entry under `images:` in inventory/image.yml, picked by image_build.yml
# via image_id). Built on Proxmox, generalized with sysprep and left as a
# Proxmox template; playbooks/image_capture.yml then turns that template
# into the <image_id>.wim the PXE server deploys - see README.md
# ("Windows image + PXE deployment")
#
# Deliberately plain virtual hardware - SATA disk, e1000e NIC - rather than
# VirtIO: the stock WinPE (the Windows 11 ISO's own boot.wim) that captures
# and deploys this image has inbox drivers for both, so neither the capture
# boot nor the image itself needs any extra drivers injected. Speed during
# the build doesn't matter; zero driver plumbing does.
#
# UEFI with Secure Boot keys NOT pre-enrolled: the capture step network-boots
# a clone of this template into iPXE, which isn't Microsoft-signed. Windows
# 11 setup's own Secure Boot/TPM checks are bypassed in autounattend.xml
# (LabConfig, client editions only - harmless on Server); a vTPM is still attached.

locals {
  # templatefile() output lands inside XML - escape anything a password
  # could contain that would otherwise break the document.
  xml_build_password = replace(replace(replace(var.build_password, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
  xml_admin_password = replace(replace(replace(var.admin_password, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
  xml_admin_user     = replace(replace(replace(var.admin_user, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
}

source "proxmox-iso" "windows" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  insecure_skip_tls_verify = var.proxmox_insecure
  node                     = var.proxmox_node
  task_timeout             = "10m"

  vm_id                = var.vm_id
  template_name        = var.template_name
  template_description = "${var.image_name} base, sysprepped. Built by Packer (ansible-runner) on ${timestamp()}. Capture to WIM with playbooks/image_capture.yml."

  os       = "win11"
  machine  = "q35"
  bios     = "ovmf"
  cpu_type = "host"
  cores    = var.cores
  memory   = var.memory

  efi_config {
    efi_storage_pool  = var.storage_pool
    efi_type          = "4m"
    pre_enrolled_keys = false
  }
  tpm_config {
    tpm_storage_pool = var.storage_pool
    tpm_version      = "v2.0"
  }

  disks {
    type         = "sata"
    disk_size    = var.disk_size
    storage_pool = var.storage_pool
    format       = "raw"
  }
  network_adapters {
    model  = "e1000e"
    bridge = var.bridge
  }

  boot_iso {
    type     = "ide"
    iso_file = var.win_iso
    unmount  = true
  }
  # autounattend.xml + first-logon script, packed into a small ISO and
  # uploaded to iso_storage for the build only.
  additional_iso_files {
    type             = "ide"
    iso_storage_pool = var.iso_storage
    unmount          = true
    cd_label         = "UNATTEND"
    cd_content = {
      "autounattend.xml" = templatefile("${abspath(path.root)}/autounattend.xml.pkrtpl", {
        build_password = local.xml_build_password
        image_name     = var.image_name
        product_key    = var.product_key
        timezone       = var.timezone
        locale         = var.locale
      })
      "firstlogon.ps1" = file("${abspath(path.root)}/scripts/firstlogon.ps1")
    }
  }

  # "Press any key to boot from CD or DVD..." only shows for a few seconds,
  # and when it appears depends on how fast the node's firmware gets there
  # (~20s on pve6). Five taps in the first 7s missed it, and the VM fell
  # through to network boot - confirmed live. So tap once a second for ~45s
  # instead; spaces landing after Setup has started are harmless. And no
  # net0 in the boot order, so a missed prompt can't reach PXE at all.
  boot         = "order=sata0;ide0"
  boot_wait    = "3s"
  boot_command = [join("", [for i in range(45) : "<spacebar><wait1>"])]

  # IP discovery for WinRM comes from the QEMU guest agent, which
  # firstlogon.ps1 installs (and prepare-sysprep.ps1 removes again).
  qemu_agent     = true
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.build_password
  winrm_timeout  = "2h"
  winrm_use_ssl  = false
}

build {
  sources = ["source.proxmox-iso.windows"]

  provisioner "powershell" {
    inline = [
      "Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force",
      "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
      "iex ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
    ]
  }

  provisioner "windows-update" {
    search_criteria = "IsInstalled=0"
    filters = [
      "exclude:$_.Title -like '*Preview*'",
      "include:$true",
    ]
  }

  # Everything the deployed PC needs at first boot to become Ansible-managed.
  provisioner "file" {
    source      = var.winrm_setup_script
    destination = "C:/Windows/Setup/Scripts/setup-winrm-ssl.ps1"
  }
  provisioner "file" {
    content = templatefile("${abspath(path.root)}/scripts/firstboot.ps1.pkrtpl", {
      controller_address = var.controller_address
    })
    destination = "C:/Windows/Setup/Scripts/firstboot.ps1"
  }
  provisioner "file" {
    content = templatefile("${abspath(path.root)}/unattend-deploy.xml.pkrtpl", {
      admin_user     = local.xml_admin_user
      admin_password = local.xml_admin_password
      timezone       = var.timezone
      locale         = var.locale
    })
    destination = "C:/Windows/System32/Sysprep/unattend-deploy.xml"
  }

  provisioner "powershell" {
    script = "${abspath(path.root)}/scripts/prepare-sysprep.ps1"
  }
}
