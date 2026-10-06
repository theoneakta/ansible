# Rocky Linux base image, built on Proxmox from the minimal ISO with a
# kickstart (playbooks/templates/rocky-ks.cfg.j2, rendered by image_build.yml
# and passed in as ks_path), and left as a Proxmox template with a cloud-init
# drive for cloning VMs. Physical machines don't get this disk image: they
# PXE-install from the same kickstart instead (image_publish_linux.yml) - the
# idiomatic way to deploy Linux, and the result matches the template.

packer {
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "~> 1.2"
    }
  }
}

variable "proxmox_url" { type = string }
variable "proxmox_token_id" { type = string }
variable "proxmox_token_secret" {
  type      = string
  sensitive = true
}
variable "proxmox_insecure" {
  type    = bool
  default = true
}
variable "proxmox_node" { type = string }
variable "storage_pool" { type = string }
variable "iso_storage" { type = string }
variable "bridge" { type = string }
variable "iso" { type = string }
variable "vm_id" { type = number }
variable "template_name" { type = string }
variable "cores" {
  type    = number
  default = 2
}
variable "memory" {
  type    = number
  default = 4096
}
variable "disk_size" {
  type    = string
  default = "32G"
}
variable "ks_path" {
  description = "Rendered kickstart (build mode) - see image_build.yml"
  type        = string
}
variable "ssh_username" { type = string }
variable "ssh_password" {
  type      = string
  sensitive = true
}

source "proxmox-iso" "rocky" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  insecure_skip_tls_verify = var.proxmox_insecure
  node                     = var.proxmox_node
  task_timeout             = "10m"

  vm_id                = var.vm_id
  template_name        = var.template_name
  template_description = "Rocky Linux base (kickstart), built by Packer (ansible-runner) on ${timestamp()}."

  os       = "l26"
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

  scsi_controller = "virtio-scsi-single"
  disks {
    type         = "scsi"
    disk_size    = var.disk_size
    storage_pool = var.storage_pool
    format       = "raw"
    discard      = true
    io_thread    = true
  }
  network_adapters {
    model  = "virtio"
    bridge = var.bridge
  }

  boot_iso {
    type     = "ide"
    iso_file = var.iso
    unmount  = true
  }
  # Anaconda loads /ks.cfg from a volume labelled OEMDRV by itself.
  additional_iso_files {
    type             = "ide"
    iso_storage_pool = var.iso_storage
    unmount          = true
    cd_label         = "OEMDRV"
    cd_content = {
      "ks.cfg" = file(var.ks_path)
    }
  }

  # GRUB's default entry is "Test this media & install"; go up one to plain
  # "Install Rocky Linux" so the build doesn't spend minutes checksumming.
  boot_wait    = "5s"
  boot_command = ["<up><wait><enter>"]

  cloud_init              = true
  cloud_init_storage_pool = var.storage_pool

  qemu_agent   = true
  communicator = "ssh"
  ssh_username = var.ssh_username
  ssh_password = var.ssh_password
  ssh_timeout  = "45m"
}

build {
  sources = ["source.proxmox-iso.rocky"]

  # Updates, then make it a clean template: fresh machine-id and SSH host
  # keys on every clone, cloud-init state reset, build-only sudo rule gone.
  provisioner "shell" {
    execute_command = "sudo -E sh -eux '{{ .Path }}'"
    inline = [
      "dnf -y update",
      "dnf clean all",
      "cloud-init clean --logs --seed || true",
      "truncate -s 0 /etc/machine-id",
      "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
      "rm -f /etc/sudoers.d/99-packer-build",
    ]
  }
}
