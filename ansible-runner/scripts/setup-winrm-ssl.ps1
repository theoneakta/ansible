#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures a Windows PC to accept Ansible connections over WinRM/HTTPS,
    matching what inventory/group_vars/windows/vars.yml expects (port 5986,
    NTLM transport, self-signed cert validation ignored).

.DESCRIPTION
    Run this ONCE on each target Windows PC (as Administrator) before adding
    it to inventory/hosts.yml. It is safe to re-run - every step checks
    current state first and only changes what is missing.

    Steps:
      1. Enable WinRM / PS Remoting (Enable-PSRemoting)
      2. Create a self-signed certificate for the HTTPS listener (unless
         -CertificateThumbprint is given to use an existing one)
      3. Create/replace the WinRM HTTPS listener on port 5986
      4. Open the Windows Firewall for that port
      5. Enable Negotiate (carries NTLM) auth on the WinRM service
      6. Set LocalAccountTokenFilterPolicy=1 - REQUIRED for any local
         (non-domain) administrator account other than the built-in
         "Administrator" (RID 500) to authenticate over the network with a
         full admin token. Without this, WinRM/WMI/remote-admin connections
         from a local admin account get silently rejected with
         "Access is denied" even with the correct password, because UAC
         filters the token down to a standard-user token for any network
         logon. See Microsoft KB947232.
      7. Raise WinRM's default operation timeout and per-shell resource
         quotas - the stock defaults (60s timeout, 1024MB/shell) are too
         tight for long-running tasks like a Chocolatey install of a large
         package (see playbooks/install_software.yml, which also runs those
         installs with async/poll for the same reason).

.PARAMETER CertificateThumbprint
    Use an existing certificate (by thumbprint) for the HTTPS listener
    instead of generating a new self-signed one.

.PARAMETER SubjectName
    Subject/CN for the self-signed certificate. Defaults to this computer's
    hostname. Only used when -CertificateThumbprint is not given.

.PARAMETER Port
    WinRM HTTPS port. Defaults to 5986, matching
    inventory/group_vars/windows/vars.yml's ansible_port.

.EXAMPLE
    .\setup-winrm-ssl.ps1

.EXAMPLE
    .\setup-winrm-ssl.ps1 -CertificateThumbprint AB12CD34...
#>
[CmdletBinding()]
param(
    [string]$CertificateThumbprint,
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$Port = 5986
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "    already set: $msg" -ForegroundColor DarkGray }

# --- 1. WinRM / PS Remoting -------------------------------------------------
Write-Step "Enabling WinRM / PS Remoting"
if ((Get-Service WinRM).Status -ne 'Running') {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Write-Ok "PS Remoting enabled and WinRM service started"
} else {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Write-Skip "WinRM service already running (re-applied config anyway)"
}

# --- 2. Certificate ----------------------------------------------------------
Write-Step "Preparing the HTTPS listener certificate"
if ($CertificateThumbprint) {
    $cert = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        throw "No certificate with thumbprint $CertificateThumbprint found in Cert:\LocalMachine\My"
    }
    Write-Ok "Using existing certificate $($cert.Thumbprint) ($($cert.Subject))"
} else {
    $existing = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$SubjectName" -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) {
        $cert = $existing
        Write-Skip "reusing valid self-signed cert $($cert.Thumbprint) for CN=$SubjectName"
    } else {
        $cert = New-SelfSignedCertificate -DnsName $SubjectName -CertStoreLocation Cert:\LocalMachine\My `
            -NotAfter (Get-Date).AddYears(10) -KeyExportPolicy Exportable `
            -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
        Write-Ok "created self-signed cert $($cert.Thumbprint) for CN=$SubjectName (valid 10 years)"
    }
}

# --- 3. HTTPS listener --------------------------------------------------------
Write-Step "Configuring the WinRM HTTPS listener on port $Port"
$listener = Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { (Get-ChildItem $_.PSPath | Where-Object Name -eq 'Transport').Value -eq 'HTTPS' }

if ($listener) {
    $currentThumbprint = (Get-ChildItem $listener.PSPath | Where-Object Name -eq 'CertificateThumbprint').Value
    if ($currentThumbprint -eq $cert.Thumbprint) {
        Write-Skip "HTTPS listener already using this certificate"
    } else {
        Write-Host "    replacing existing HTTPS listener (was using cert $currentThumbprint)"
        $listener | Remove-Item -Recurse -Force
        New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
            -Hostname $SubjectName -CertificateThumbPrint $cert.Thumbprint -Port $Port -Force | Out-Null
        Write-Ok "HTTPS listener recreated with new certificate on port $Port"
    }
} else {
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
        -Hostname $SubjectName -CertificateThumbPrint $cert.Thumbprint -Port $Port -Force | Out-Null
    Write-Ok "HTTPS listener created on port $Port"
}

# --- 4. Firewall ---------------------------------------------------------------
Write-Step "Opening the firewall for TCP $Port"
$ruleName = "WinRM over HTTPS ($Port)"
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
    Write-Skip "firewall rule '$ruleName' already exists"
} else {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    Write-Ok "firewall rule '$ruleName' created"
}

# --- 5. Auth (Negotiate carries NTLM) ------------------------------------------
Write-Step "Enabling Negotiate authentication on the WinRM service"
if ((Get-Item WSMan:\localhost\Service\Auth\Negotiate).Value -eq $true) {
    Write-Skip "Negotiate auth already enabled"
} else {
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
    Write-Ok "Negotiate auth enabled"
}

# --- 6. UAC remote token filtering for local admin accounts --------------------
Write-Step "Disabling UAC remote token filtering for local administrator accounts"
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacName = 'LocalAccountTokenFilterPolicy'
$current = (Get-ItemProperty -Path $uacPath -Name $uacName -ErrorAction SilentlyContinue).$uacName
if ($current -eq 1) {
    Write-Skip "LocalAccountTokenFilterPolicy already set to 1"
} else {
    New-ItemProperty -Path $uacPath -Name $uacName -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Ok "LocalAccountTokenFilterPolicy set to 1 (local admins now get a full token over the network)"
}

# --- 7. Timeouts and shell quotas ------------------------------------------------
Write-Step "Raising WinRM operation timeout and per-shell resource limits"
$serviceSettings = @{
    'WSMan:\localhost\MaxTimeoutms'                         = 1800000   # 30 min (matches playbook async ceiling)
    'WSMan:\localhost\Shell\MaxMemoryPerShellMB'            = 2048
    'WSMan:\localhost\Shell\MaxProcessesPerShell'           = 50
    'WSMan:\localhost\Shell\MaxShellsPerUser'               = 10
    'WSMan:\localhost\Shell\MaxConcurrentUsers'             = 10
}
foreach ($path in $serviceSettings.Keys) {
    $desired = $serviceSettings[$path]
    $currentValue = (Get-Item $path).Value
    if ([int64]$currentValue -ge $desired) {
        Write-Skip "$path already $currentValue"
    } else {
        Set-Item $path -Value $desired -Force
        Write-Ok "$path set to $desired (was $currentValue)"
    }
}

# --- Restart WinRM to apply everything ------------------------------------------
Write-Step "Restarting WinRM service"
Restart-Service WinRM -Force
Write-Ok "WinRM restarted"

# --- Summary ----------------------------------------------------------------------
Write-Step "Done - current HTTPS listener:"
winrm enumerate winrm/config/listener | Select-String -Pattern 'Transport|Port|CertificateThumbprint|Hostname'

Write-Host ""
Write-Host "This host should now be reachable by the ansible-runner playbooks over:" -ForegroundColor Yellow
Write-Host "  ansible_connection: winrm"
Write-Host "  ansible_port: $Port"
Write-Host "  ansible_winrm_transport: ntlm"
Write-Host "  ansible_winrm_server_cert_validation: ignore   # self-signed cert"
Write-Host ""
Write-Host "Add this PC to inventory/hosts.yml under the 'windows' group and test with:" -ForegroundColor Yellow
Write-Host "  ./run.sh --ping"
