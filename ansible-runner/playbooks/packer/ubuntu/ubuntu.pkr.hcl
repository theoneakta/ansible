# Ubuntu base image (Server, or Desktop = Server + ubuntu-desktop), built on
# Proxmox from the live-server ISO with an autoinstall answer file
# (playbooks/templates/ubuntu-autoinstall.yaml.j2, rendered by
# image_build.yml and passed in as user_data_path), and left as a Proxmox
# template with a cloud-init drive for cloning VMs. Physical machines
# PXE-install from the same answer file instead (image_publish_linux.yml) -
# same approach as packer/rocky/.

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
variable "template_label" {
  type    = string
  default = "Ubuntu"
}
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
variable "user_data_path" {
  description = "Rendered autoinstall user-data (build mode) - see image_build.yml"
  type        = string
}
variable "ssh_username" { type = string }
variable "ssh_password" {
  type      = string
  sensitive = true
}

source "proxmox-iso" "ubuntu" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  insecure_skip_tls_verify = var.proxmox_insecure
  node                     = var.proxmox_node
  task_timeout             = "10m"

  vm_id                = var.vm_id
  template_name        = var.template_name
  template_description = "${var.template_label} (autoinstall), built by Packer (ansible-runner) on ${timestamp()}."

  # SeaBIOS like the Rocky template: the boot command below drives the ISO's
  # GRUB, which is the same under BIOS, and clones boot the same way.
  os       = "l26"
  machine  = "q35"
  bios     = "seabios"
  cpu_type = "host"
  cores    = var.cores
  memory   = var.memory

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
  # The installer's cloud-init reads user-data/meta-data from a volume
  # labelled "cidata" by itself (NoCloud).
  additional_iso_files {
    type             = "ide"
    iso_storage_pool = var.iso_storage
    unmount          = true
    cd_label         = "cidata"
    cd_content = {
      "user-data" = file(var.user_data_path)
      "meta-data" = ""
    }
  }

  # At the GRUB menu, drop to its command line and boot the installer with
  # "autoinstall" on the kernel line - without it Subiquity stops to ask
  # "Continue with autoinstall?" even with an answer file present.
  boot_wait = "15s"
  boot_command = [
    "c<wait3>",
    "linux /casper/vmlinuz autoinstall ds=nocloud ---<enter><wait3>",
    "initrd /casper/initrd<enter><wait3>",
    "boot<enter>",
  ]

  cloud_init              = true
  cloud_init_storage_pool = var.storage_pool

  qemu_agent   = true
  communicator = "ssh"
  ssh_username = var.ssh_username
  ssh_password = var.ssh_password
  # The desktop variant downloads and installs a few thousand packages, on
  # storage that can be slow (VM disks on the TrueNAS over iSCSI).
  ssh_timeout = "180m"
}

build {
  sources = ["source.proxmox-iso.ubuntu"]

  # Updates, then make it a clean template: fresh machine-id and SSH host
  # keys on every clone, cloud-init state reset so Proxmox's cloud-init drive
  # applies to clones, build-only sudo rule gone.
  provisioner "shell" {
    execute_command = "sudo -E sh -eux '{{ .Path }}'"
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get update",
      "apt-get -y full-upgrade",
      "apt-get -y autoremove --purge",
      "apt-get clean",
      # The installer's own cloud-init settings would make clones ignore
      # Proxmox's cloud-init drive.
      "rm -f /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg",
      "cloud-init clean --logs --seed || true",
      "truncate -s 0 /etc/machine-id",
      "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
      "rm -f /etc/sudoers.d/99-packer-build",
    ]
  }
}
