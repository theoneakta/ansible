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

# QEMU guest agent: from a virtio-win ISO if one happens to be attached,
# otherwise straight from the virtio-win project.
$msi = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root 'guest-agent\qemu-ga-x86_64.msi' } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msi) {
    $msi = 'C:\Windows\Temp\qemu-ga-x86_64.msi'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-qemu-ga/qemu-ga-x86_64.msi' -OutFile $msi -UseBasicParsing
}
Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait

Stop-Transcript
