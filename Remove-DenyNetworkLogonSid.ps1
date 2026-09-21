<#
.SYNOPSIS
    Removes one or more SIDs from a user-rights assignment (default: SeDenyNetworkLogonRight)
    on the local machine. Touches only that one right and saves a backup first.

.PARAMETER Sid
    SIDs to remove. Default: S-1-5-113 (Local account).
    Add S-1-5-114 (Local account and member of Administrators group) if needed.

.PARAMETER Right
    Privilege constant to edit. Default: SeDenyNetworkLogonRight.

.EXAMPLE
    .\Remove-DenyNetworkLogonSid.ps1

.EXAMPLE
    .\Remove-DenyNetworkLogonSid.ps1 -Sid S-1-5-113,S-1-5-114 -Confirm:$false

.EXAMPLE
    Invoke-Command -ComputerName srv01,srv02 -FilePath .\Remove-DenyNetworkLogonSid.ps1

.NOTES
    Undo: secedit /configure /db $env:TEMP\undo.sdb /cfg <backup path printed below> /areas USER_RIGHTS
    A GPO / baseline refresh will re-apply the original value.
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string[]]$Sid = @('S-1-5-113'),
    [string]$Right = 'SeDenyNetworkLogonRight'
)

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$backup = Join-Path $env:TEMP "userrights_backup_$($env:COMPUTERNAME)_$stamp.inf"
$work   = Join-Path $env:TEMP "userrights_work_$stamp"

# 1. Export current rights (also serves as the backup)
secedit /export /cfg $backup /areas USER_RIGHTS /quiet
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $backup)) { throw 'secedit export failed.' }

# 2. Read the current value of the one right we care about
$line = Select-String -Path $backup -Pattern "^\s*$Right\s*=" | Select-Object -First 1
if (-not $line) { Write-Host "$Right is not defined on this machine. Nothing to do."; return }

$items = ($line.Line -split '=', 2)[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$keep  = @($items | Where-Object { $_.TrimStart('*') -notin $Sid })

if ($keep.Count -eq $items.Count) {
    Write-Host "None of [$($Sid -join ', ')] found in $Right. Nothing to do."
    Write-Host "Current: $($items -join ', ')"
    return
}

Write-Host "Current : $($items -join ', ')"
Write-Host "New     : $(if ($keep) { $keep -join ', ' } else { '(empty)' })"

# 3. Apply a minimal template containing only this right (UTF-16, as secedit expects)
@(
    '[Unicode]', 'Unicode=yes',
    '[Version]', 'signature="$CHICAGO$"', 'Revision=1',
    '[Privilege Rights]', "$Right = $($keep -join ',')"
) | Set-Content -Path "$work.inf" -Encoding Unicode

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Remove $($Sid -join ', ') from $Right")) {
    secedit /configure /db "$work.sdb" /cfg "$work.inf" /areas USER_RIGHTS /quiet
    if ($LASTEXITCODE -ne 0) { Write-Error "secedit configure failed (exit $LASTEXITCODE)."; }
    else {
        # 4. Verify
        $verify = Join-Path $env:TEMP "userrights_verify_$stamp.inf"
        secedit /export /cfg $verify /areas USER_RIGHTS /quiet
        Select-String -Path $verify -Pattern "^\s*$Right\s*=" | ForEach-Object { "Verified: $($_.Line)" }
        Remove-Item $verify -Force -ErrorAction SilentlyContinue
        Write-Host "Backup  : $backup"
        Write-Warning 'A GPO or baseline re-run will revert this. Prefer a domain service account long-term.'
    }
}

Remove-Item "$work.inf", "$work.sdb", "$work.jfm" -Force -ErrorAction SilentlyContinue