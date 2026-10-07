# Runs once, at the build VM's first (auto)logon, from autounattend.xml's
# FirstLogonCommands. Build-time only: opens plain-HTTP WinRM for Packer and
# installs the QEMU guest agent (Packer finds the VM's IP through it). Both
# are removed again by prepare-sysprep.ps1 / firstboot.ps1, so neither ends
# up active on a deployed PC.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\Windows\Temp\packer-firstlogon.log

# Network profile Private, or WinRM's firewall rules refuse to open.
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# No sleep while Windows Update runs for an hour.
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /hibernate off

# Store app auto-updates during the build are the classic cause of sysprep
# failing with "package was installed for a user, but not provisioned for
# all users".
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name AutoDownload -Value 2 -Type DWord

# WinRM over HTTP with Basic auth - for Packer only, on the build VM only.
winrm quickconfig -quiet -force
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\MaxTimeoutms -Value 1800000
New-NetFirewallRule -Name 'Packer-WinRM-HTTP' -DisplayName 'Packer WinRM HTTP (build only)' `
    -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any | Out-Null
Set-Service WinRM -StartupType Automatic
Restart-Service WinRM

# QEMU guest agent - and the VirtIO serial driver it talks to Proxmox
# through, which Windows doesn't have inbox. virtio-win's guest tools
# install both (the virtio-win ISO is attached by windows.pkr.hcl); the
# agent-only MSI below is just a fallback and is useless without that driver.
$tools = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root 'virtio-win-guest-tools.exe' } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($tools) {
    Start-Process $tools -ArgumentList '/install', '/quiet', '/norestart' -Wait
    Stop-Transcript
    return
}
$msi = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root 'guest-agent\qemu-ga-x86_64.msi' } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msi) {
    $msi = 'C:\Windows\Temp\qemu-ga-x86_64.msi'
    # curl.exe (built into Windows 10/11/Server), not Invoke-WebRequest: the
    # "latest" URL redirects https -> http, which Windows PowerShell 5.1
    # won't follow - it saved the 4 KB redirect page as the "MSI", msiexec
    # failed silently, and Packer waited forever for an agent that never
    # came - confirmed live.
    curl.exe -fsSL --retry 5 -o $msi 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-qemu-ga/qemu-ga-x86_64.msi'
}
if ((Get-Item $msi -ErrorAction SilentlyContinue).Length -lt 1MB) {
    throw "QEMU guest agent download failed - $msi is missing or too small to be the installer."
}
Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait

Stop-Transcript
