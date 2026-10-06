# Last Packer provisioner: undo build-only changes, arrange the first-boot
# WinRM setup for deployed PCs, then generalize with sysprep. Uses /quit, not
# /shutdown - Packer's Proxmox builder shuts the VM down itself (through the
# Proxmox API) right after this, before converting it to a template.
$ErrorActionPreference = 'Stop'

# 1. First-boot task: firstboot.ps1 makes the deployed PC Ansible-manageable
#    (setup-winrm-ssl.ps1) without anyone logging on. A SYSTEM scheduled task
#    rather than SetupComplete.cmd, which Windows skips on PCs activated with
#    an OEM firmware key - exactly the PCs this image is meant for.
#    Re-runs every 5 minutes until it succeeds, then deletes itself.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Setup\Scripts\firstboot.ps1'
$triggers = @(
    New-ScheduledTaskTrigger -AtStartup
    New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName 'FirstBoot-AnsibleWinRM' -Action $action -Trigger $triggers -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

# 2. Build-only pieces out.
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' -Name PreventDeviceEncryption -ErrorAction SilentlyContinue
$ga = Get-CimInstance Win32_Product -Filter "Name LIKE 'QEMU guest agent%'" -ErrorAction SilentlyContinue
if ($ga) { Start-Process msiexec.exe -ArgumentList '/x', $ga.IdentifyingNumber, '/qn', '/norestart' -Wait }
Remove-Item 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue

# 3. Appx packages installed for a user but not provisioned for all users
#    make sysprep /generalize fail outright.
$provisioned = (Get-AppxProvisionedPackage -Online).PackageName
Get-AppxPackage -AllUsers | Where-Object { -not $_.NonRemovable -and $_.PackageFullName -notin $provisioned -and $_.SignatureKind -ne 'System' } |
    ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }

# 4. Component store cleanup keeps the captured WIM smaller.
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null

# 5. Generalize.
$sysprep = Start-Process -FilePath "$env:SystemRoot\System32\Sysprep\sysprep.exe" `
    -ArgumentList '/generalize', '/oobe', '/quit', '/quiet', "/unattend:$env:SystemRoot\System32\Sysprep\unattend-deploy.xml" `
    -Wait -PassThru
$state = (Get-ItemProperty 'HKLM:\SYSTEM\Setup\Status\SysprepStatus' -ErrorAction SilentlyContinue).GeneralizationState
if ($state -ne 7) {
    Get-Content "$env:SystemRoot\System32\Sysprep\Panther\setuperr.log" -Tail 40 -ErrorAction SilentlyContinue
    throw "sysprep /generalize did not complete (exit $($sysprep.ExitCode), GeneralizationState=$state) - see setuperr.log above."
}
# Sysprep has cached the answer file in Panther for the deployed PC's
# first boot; the copy holding the admin password isn't needed any more.
Remove-Item "$env:SystemRoot\System32\Sysprep\unattend-deploy.xml" -Force
Write-Output 'Sysprep generalize complete.'
