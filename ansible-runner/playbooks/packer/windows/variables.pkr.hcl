# Every value comes from playbooks/image_build.yml (as PKR_VAR_* environment
# variables, so secrets never appear on a command line). Defaults here are
# only for running `packer validate` by hand.

variable "proxmox_url" {
  type    = string
  default = "https://192.168.3.236:8006/api2/json"
}
variable "proxmox_token_id" {
  type    = string
  default = "ansible@pam!ansible"
}
variable "proxmox_token_secret" {
  type      = string
  sensitive = true
  default   = ""
}
variable "proxmox_insecure" {
  type    = bool
  default = true
}
variable "proxmox_node" {
  type    = string
  default = "pve5"
}
variable "storage_pool" {
  type    = string
  default = "local-lvm"
}
variable "iso_storage" {
  type    = string
  default = "local"
}
variable "bridge" {
  type    = string
  default = "vmbr0"
}
variable "win_iso" {
  description = "Windows 11 ISO already on Proxmox, e.g. local:iso/Win11_25H2_English_x64.iso"
  type        = string
  default     = ""
}
variable "virtio_iso" {
  description = "virtio-win ISO on Proxmox - its guest tools give Windows the VirtIO serial driver the QEMU guest agent needs"
  type        = string
  default     = "local:iso/virtio-win.iso"
}
variable "image_name" {
  description = "Edition to install, as named inside install.wim/esd"
  type        = string
  default     = "Windows 11 Pro"
}
variable "product_key" {
  description = "Install key that selects the edition (empty for evaluation media)"
  type        = string
  default     = ""
}
variable "boot_menu" {
  description = "The ISO shows a Windows Boot Manager menu (Server media): press Enter on it"
  type        = bool
  default     = false
}
variable "vm_id" {
  type    = number
  default = 9011
}
variable "template_name" {
  type    = string
  default = "win11-pro-base"
}
variable "cores" {
  type    = number
  default = 4
}
variable "memory" {
  type    = number
  default = 8192
}
variable "disk_size" {
  type    = string
  default = "64G"
}
variable "build_password" {
  description = "Temporary built-in Administrator password, only used during the build (random per build)"
  type        = string
  sensitive   = true
  default     = ""
}
variable "admin_user" {
  description = "Local administrator created on every deployed PC"
  type        = string
  default     = ""
}
variable "admin_password" {
  type      = string
  sensitive = true
  default   = ""
}
variable "timezone" {
  type    = string
  default = "Eastern Standard Time"
}
variable "locale" {
  type    = string
  default = "en-US"
}
variable "controller_address" {
  description = "Only this address may reach WinRM on deployed PCs (setup-winrm-ssl.ps1 -ControllerAddress)"
  type        = string
  default     = "192.168.3.8"
}
variable "winrm_setup_script" {
  type    = string
  default = "/ansible/scripts/setup-winrm-ssl.ps1"
}
