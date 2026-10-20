# Legacy Windows in-place OS upgrades: runbook and change log

This is the working notes for a migration project that moves many legacy Windows Servers, each running an application plus SQL Server, to a newer OS **in place**. Only the OS changes; apps, data, roles and settings are kept.

The first server, `SQL2005` (lab VM 118 on pve6), is the pilot. Every finding goes into the runbook below so the next servers run faster.

## Upgrade path rules (Microsoft)

| From | To (in place) | Notes |
|---|---|---|
| 2008 R2 SP1 | 2012 / **2012 R2** | Supported. Needs SP1. |
| 2012 R2 | 2016 / 2019 | Supported |
| 2016 | 2019 / 2022 | Supported |
| 2019 / 2022 | 2022 / 2025 | Supported |

- **Same edition or higher:** Standard → Standard or Datacenter. Never Datacenter → Standard.
- **Evaluation media can't upgrade a licensed edition.** Setup only offers "Custom: install Windows only" (a clean install).
- **Same install language.** The setup ISO's language must match the OS *install* language: `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language\InstallLanguage`. An added language pack doesn't count.
- **Same architecture.** x64 to x64 only. Core ↔ GUI can't be switched during the upgrade.
- A domain controller needs adprep first. Plan it separately.

## Pre-flight checklist (per server)

1. **ISO check** (no mounting on the server needed):
   - read `sources\ei.cfg`, where `Channel=eval` is a blocker;
   - read the `install.wim` XML header for EDITIONID (`ServerStandardEval` = eval), build and language;
   - read `sources\lang.ini`.
2. **Server baseline** (read-only, kept with the server's change record): OS, edition, build, InstallLanguage, MUI, activation, hotfix count, C: free space (≥ 20 GB), roles and features, key services with start mode, SQL patch level and service account, IIS sites and app pools, custom firewall rules, network config, installed software, and an application health check.
3. **App compatibility:** check every installed product against the target OS (see the matrix below).
4. **Snapshot or backup** of the VM before setup starts. On Proxmox, an LVM-thin snapshot is enough for a lab; production needs a backup.
5. **Change window:** the upgrade takes 30–90 min with several reboots, and the app is down throughout.

## Product compatibility notes

| Product | On 2012 R2 | On 2016+ | Notes |
|---|---|---|---|
| SQL Server 2005 SP4 | **Not supported**, but usually works | Not supported | Upgrade setup lists it as a compatibility issue. Plan to move the databases to a supported SQL version (2012 SP4+ can restore 2005 backups) as a follow-up project. |
| IIS 7.5 → 8.5 | Upgraded in place | — | Sites, app pools and `web.config` carry over. ASP.NET 2.0/3.5 needs the .NET 3.5 feature, which setup normally keeps. |
| .NET 3.5 | Feature kept | Feature on demand | |

## Gotchas found so far

- **Russian-installed server (InstallLanguage 0419) + English upgrade ISO:** setup refuses to keep apps and files. Two ways around it:
  - **(a) Supported:** a target ISO in the same install language.
  - **(b) Known workaround, unsupported by Microsoft:** the en-US language pack must already be installed. Set `InstallLanguage` (and `Default`) to `0409` before running setup.
- The built-in account and group names stay localized forever: `Администратор`, `NT AUTHORITY\СИСТЕМА`. Scripts must use SIDs or the localized names.
- **2008 R2 tooling:** PowerShell 2.0, WinRM 2.0, default ExecutionPolicy `Restricted`.
  - `winrm quickconfig` fails on a partly localized OS. Configure the listener and the firewall rule by hand.
  - pywinrm's `run_ps` is limited by the 8191-character command line. Upload scripts as files.

## Server log

### SQL2005 (VM 118, 192.168.3.103): Windows Server 2008 R2 SP1 → 2012 R2

**Baseline, 2026-10-19:**

| Item | Value |
|---|---|
| OS | Windows Server 2008 R2 Standard SP1, 6.1.7601 |
| Install language / MUI | ru-RU (0419) / ru-RU, en-US. The UI is forced to en-US by policy. |
| Activation | ServerStandard, not activated (grace period, 30 days left) |
| Hotfixes | 1 |
| Hardware | 2 vCPU, 8 GB RAM, 60 GB disk (42 GB free), e1000 NIC, SATA disk, SeaBIOS |
| Roles/features | IIS 7.5 (static content, default doc, ASP.NET 2.0/3.5, ISAPI, logging, request filtering, management console), .NET 3.5.1 |
| SQL | SQL Server 2005 SP4 Standard x64 (9.00.5000), default instance, mixed auth, NetworkService. Databases: roster_db plus the system databases. |
| App | "Celtics Hub". IIS site `Celtics` (port 80, app pool .NET 2.0 integrated), read-only DB access through `IIS APPPOOL\Celtics`. An external feeder (.8) writes hourly as SQL login `celtics_feeder`. Health check: `http://192.168.3.103/api/health`. |
| Services | MSSQLSERVER, SQLSERVERAGENT, SQLBrowser, SQLWriter, W3SVC, WinRM, MSDTC: Auto/Running. TermService: Manual/Running. |
| Firewall | Windows rules: Lab HTTP 80, Lab RDP 3389, Lab SQL 1433, Lab SQL Browser 1434, WinRM5985 (from .8 only), ping. The Proxmox per-VM firewall mirrors them. |
| Network | DHCP 192.168.3.103, gateway and DNS 192.168.3.1 |

**Pre-flight result, 2026-10-19: BLOCKED.**
- `WinServer_2012_R2_English_x64.iso` (SHA-1 849734f3…, label `IR3_SSS_X64FREE_EN-US_DV9`) is **Evaluation** media: `ei.cfg Channel=eval`, editions `ServerStandardEval` and `ServerDatacenterEval`. It can't upgrade a licensed `ServerStandard`.
- The language doesn't match either: the ISO is en-US, the server's install language is ru-RU.
- **Needed:** a non-evaluation (retail, VL or MSDN) Windows Server 2012 R2 Standard ISO. Russian is the supported route; English works only with the InstallLanguage workaround.

**Changes made:** none. Only the read-only baseline and the ISO inspection.

**Status:** on hold (user decision, 2026-10-19). The server stays on 2008 R2 until a non-evaluation 2012 R2 Standard ISO is available. When it is, resume at the pre-flight checklist: check the ISO, snapshot, then upgrade.
