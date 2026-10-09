# Last in-guest Packer provisioner: undo build-only changes, arrange the first-boot
# WinRM setup for deployed PCs, then start sysprep (generalize + shutdown) as a
# SYSTEM task - windows.pkr.hcl waits for the power-off, then Packer converts
# the VM to a template.
$ErrorActionPreference = 'Stop'

# 1. First-boot task: firstboot.ps1 makes the deployed PC Ansible-manageable
#    (setup-winrm-ssl.ps1) without anyone logging on. A SYSTEM scheduled task
#    rather than SetupComplete.cmd, which Windows skips on PCs activated with
#    an OEM firmware key - exactly the PCs this image is meant for.
#    Runs at startup, then every 5 minutes until it succeeds, then deletes
#    itself. The repetition hangs off the startup trigger, so nothing fires
#    on this build VM (its next boot is the deployed PC's): a separate
#    "once, now, repeat every 5 minutes" trigger ran firstboot.ps1 here,
#    5 minutes in - it reconfigured WinRM under Packer ("connection reset by
#    peer") and deleted itself from the image - confirmed live on Server 2025.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Setup\Scripts\firstboot.ps1'
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 365)).Repetition
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName 'FirstBoot-AnsibleWinRM' -Action $action -Trigger $trigger -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

# 1b. IPv6 off on every interface (Microsoft's documented DisabledComponents
#     switch; 0xFF = all IPv6 components). Survives sysprep and takes effect
#     from the deployed PC's first boot. Note Microsoft's own caveat: some
#     Windows features assume IPv6 (e.g. HomeGroup-era features, DirectAccess)
#     - none of which this toolkit's targets use.
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents `
    -Value 0xFF -PropertyType DWord -Force | Out-Null

# 2. Build-only pieces out.
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' -Name PreventDeviceEncryption -ErrorAction SilentlyContinue
$ga = Get-CimInstance Win32_Product -Filter "Name LIKE 'QEMU guest agent%'" -ErrorAction SilentlyContinue
if ($ga) { Start-Process msiexec.exe -ArgumentList '/x', $ga.IdentifyingNumber, '/qn', '/norestart' -Wait }
Remove-Item 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue

# 3. Appx packages installed for a user but not provisioned for all users
#    make sysprep /generalize fail outright.
#    Frameworks are skipped (they go with the apps that use them), and each
#    removal is wrapped: Remove-AppxPackage throws a terminating COM error -
#    not stopped by -ErrorAction - e.g. "cannot remove framework ... because
#    Microsoft.Paint depends on it", which aborted the build - confirmed live.
$provisioned = (Get-AppxProvisionedPackage -Online).PackageName
Get-AppxPackage -AllUsers |
    Where-Object { -not $_.NonRemovable -and -not $_.IsFramework -and $_.PackageFullName -notin $provisioned -and $_.SignatureKind -ne 'System' } |
    ForEach-Object {
        try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop }
        catch { Write-Output "Couldn't remove $($_.TargetObject): $($_.Exception.Message)" }
    }

# 4. Component store cleanup keeps the captured WIM smaller.
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null

# 5. Generalize - from a SYSTEM scheduled task, not over this WinRM session:
#    sysprep /generalize resets the network adapter and the built-in
#    Administrator, which dropped Packer's connection mid-run ("connection
#    reset by peer") and left no way to log back in - confirmed live. The
#    task runs sysprep with /shutdown, which only powers off when
#    generalization succeeded; windows.pkr.hcl's next step waits for that
#    power-off through the Proxmox API (no WinRM). firstboot.ps1 removes the
#    task and the answer-file copy on deployed PCs.
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\Sysprep\sysprep.exe" `
    -Argument "/generalize /oobe /shutdown /quiet /unattend:$env:SystemRoot\System32\Sysprep\unattend-deploy.xml"
Register-ScheduledTask -TaskName 'Packer-Sysprep' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'Packer-Sysprep'
Write-Output 'Sysprep started (generalize + shutdown); waiting for power-off from outside.'
# Packer judges the script by $LASTEXITCODE - e.g. DISM's above, which can be
# non-zero on success. Real failures here already threw.
exit 0
