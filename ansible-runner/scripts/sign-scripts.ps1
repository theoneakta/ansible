#Requires -Version 5.1
<#
.SYNOPSIS
    Re-signs every .ps1 file in this folder with the ansible-runner code
    signing certificate (self-signed - see README.md, "Code signing").

.DESCRIPTION
    Run this after editing any script in scripts/ - any content change
    invalidates its existing signature. Looks up the certificate by
    thumbprint in Cert:\CurrentUser\My; the private key only exists on
    whichever machine generated it (this one, unless you exported and
    imported a .pfx elsewhere).

    If the certificate is missing (new machine, lost store, etc.), generate
    a new one first:

        $cert = New-SelfSignedCertificate -Subject "CN=Ansible Runner Code Signing, O=theoneakta ansible-runner" `
            -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My `
            -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddYears(10) -HashAlgorithm SHA256
        Export-Certificate -Cert $cert -FilePath .\ansible-runner-codesign.cer

    Then update -Thumbprint below (or pass -Thumbprint) and commit the new
    .cer - anyone who trusted the old one will need to trust the new one too.

.PARAMETER Thumbprint
    Defaults to the certificate generated for this project. Override if you
    regenerated the cert (see above) or use a different one.
#>
[CmdletBinding()]
param(
    [string]$Thumbprint = "5D6095016C3A8903A2031441FB2F4D61A7F2BE34"
)

$ErrorActionPreference = 'Stop'

$cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $cert) {
    throw "No code signing certificate with thumbprint $Thumbprint in Cert:\CurrentUser\My on this machine. See this script's header comment to generate one."
}

$scripts = Get-ChildItem -Path $PSScriptRoot -Filter *.ps1
foreach ($script in $scripts) {
    $sig = Set-AuthenticodeSignature -FilePath $script.FullName -Certificate $cert -HashAlgorithm SHA256
    $color = if ($sig.Status -eq 'Valid' -or $sig.Status -eq 'UnknownError') { 'Green' } else { 'Red' }
    Write-Host "$($script.Name): $($sig.Status)" -ForegroundColor $color
}
Write-Host "`nNote: 'UnknownError' just means this cert's root isn't in this machine's trust store yet - the signature itself is still valid. See README.md for how to trust it." -ForegroundColor DarkGray

# SIG # Begin signature block
# MIIGIgYJKoZIhvcNAQcCoIIGEzCCBg8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDwEMxvsJTc+gNZ
# YC53P7DUNjUlU0BZWTpW7xpv56dgyaCCA2gwggNkMIICTKADAgECAhBP1f8n+3BX
# kEkvCDFRRbjlMA0GCSqGSIb3DQEBCwUAMEoxIjAgBgNVBAoMGXRoZW9uZWFrdGEg
# YW5zaWJsZS1ydW5uZXIxJDAiBgNVBAMMG0Fuc2libGUgUnVubmVyIENvZGUgU2ln
# bmluZzAeFw0yNjA5MjIwMjEzMzJaFw0zNjA5MjIwMjIzMzJaMEoxIjAgBgNVBAoM
# GXRoZW9uZWFrdGEgYW5zaWJsZS1ydW5uZXIxJDAiBgNVBAMMG0Fuc2libGUgUnVu
# bmVyIENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMnHL9o0LIFQOozky77khlfcVxL52+PS3LEveNlLTmscDiGbbAQ7cqhVeC2sCzHA
# SWSGXVEZIP85lZCfxzievkagvf2FKhzNQp8GDKJ0sZupo57eq913xiAKGXjrNgnC
# 6yZ0jHzN9yaHvMTretcuClx4JMwTgwecJK5kuPztazsQHAylEAoVqZq44HLr5I8A
# WPhhr2mIh/OiCO9SLO1/EspQAz8MN4W7GO1PYyhiH2US1/vLTV8Lg3O9G6pR+iSs
# C3YSyqIF1zNxhu8ApUV5AxKtZ8h+dGlKG7WKfFpEHLi4FzHYjPl0N7CDgUEL7K94
# yBCLSzDqKI6WrrIzVTEqMqECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSD3mbguJnjSh2RMr3fyCcOSs+KSzAN
# BgkqhkiG9w0BAQsFAAOCAQEAXZKiSG9JY7ru4z+YeywM5HcToAsZ1xdJtMcmCPj3
# MAtMerNrY09Qi/3LMSS6J2hVQPchfmkFR3sIZs3rGFJ0IdP8829z3HJrzAN0xeG/
# FqkK3s//z+MOMovVrx3fmYcOFD2LxJ9JEu2TsfGnZksr945UjExNLpJJq95jO/m4
# xOM3kP/yTbRT+u2QGADAqdNqSTeGaE+/2xa+4D6qqPueo5o+xfH3MH4NN3qNAUkp
# cE3tXqM4GrfT4v5jO1Ymj3KQSNTfskuh7OXeuccouJrfg3XdrefZnS7WMJ9OXa5O
# 5zL6ajMeA0SMahzArqoXiXWZ9COcPthJQk32Yd7lTy3mbzGCAhAwggIMAgEBMF4w
# SjEiMCAGA1UECgwZdGhlb25lYWt0YSBhbnNpYmxlLXJ1bm5lcjEkMCIGA1UEAwwb
# QW5zaWJsZSBSdW5uZXIgQ29kZSBTaWduaW5nAhBP1f8n+3BXkEkvCDFRRbjlMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEINrcvnqDqS4KUpKxBY486WfVIjH12G1/uxpc3JO6
# 7jJxMA0GCSqGSIb3DQEBAQUABIIBAFUMpk1UgzU0Q0medVIRmmWl6Hcp8gvohwcy
# X6Wt6qlFA2as/StYRm0MLGXVUkigwow3WbDkRD4Sg9s4hFzavq0GvN5z3ZJd6QBf
# 1JWFd0r3wdKQAFeZ+4oxycOt2hu5sXJtAdKsx6rISqq1qNedRyVqWwURHnpjDDH+
# 49nzbUj71isC7n4fI9AoYBLIVEOmj+j3aSOhvP9Px7YeGk02+6AWNMl6tgo4SqPw
# xA+KThoGg9J0cC5lHJ4x+5DP0ujlDCXShwjZThwlqLNKttXywoOVVgwuUVOtZTVK
# 52Nce4bsEHupHbMKmJWpjS+WJVDrUhNJmwB1WvH6rAbP6wV6Zss=
# SIG # End signature block
