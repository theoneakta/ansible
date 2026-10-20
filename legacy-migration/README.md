# Legacy Windows in-place OS upgrades: runbook and change log

This is the working notes for a migration project that moves many legacy Windows Servers, each running an application plus SQL Server, to a newer OS **in place**. Only the OS changes; apps, data, roles and settings are kept.

The first server, `SQL2005` (lab VM 118 on pve6), is the pilot. Every finding goes into the runbook below so the next servers run faster.

## Upgrade path rules (Microsoft)

Source: Microsoft, [Plan your Windows Server upgrade path](https://learn.microsoft.com/en-us/windows-server/get-started/install-upgrade-migrate) (updated 2026-04-14), installation-media tab. Since Windows Server 2025, a non-clustered server can upgrade **up to four versions** in one step; 2022 and earlier allow at most two. A cluster OS rolling upgrade goes one version at a time.

| From \ To (in place) | 2012 R2 | 2016 | 2019 | 2022 | 2025 |
|---|---|---|---|---|---|
| 2008 R2 SP1 | ✅ (older guidance; no longer in the current table) | — | — | — | — |
| 2012 | ✅ | ✅ | — | — | — |
| 2012 R2 | — | ✅ | ✅ | ❌ (not supported) | ✅ |
| 2016 | — | — | ✅ | ✅ | ✅ |
| 2019 | — | — | — | ✅ | ✅ |
| 2022 | — | — | — | — | ✅ |

**Target path for this project:** 2008 R2 SP1 → 2012 R2 → **2025**. That's two upgrades and two licenses, because each Windows Server upgrade needs its own license.

- **Same edition or higher:** Standard → Standard or Datacenter. Never Datacenter → Standard.
- **Evaluation media can't upgrade a licensed edition.** Setup only offers "Custom: install Windows only" (a clean install).
- **Standard can move to Datacenter during an upgrade, never the reverse.**
- **Same install language.** The setup ISO's language must match the OS *install* language: `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language\InstallLanguage`. An added language pack doesn't count.
- **Same architecture.** x64 to x64 only. Core ↔ GUI can't be switched during the upgrade.
- A domain controller needs adprep first. Plan it separately.

## Pre-flight checklist (per server)

1. **ISO check** (no mounting on the server needed):
   - **authenticity first.** Compare the SHA-1/SHA-256 with Microsoft's published value (MSDN/VLSC). Then look for signs of repackaging, any one of which means you reject the ISO:
     - `NTLite.log` or other tool logs at the root;
     - an `autounattend.xml` at the root;
     - `sources\$OEM$` (especially `Setup\Scripts\SetupComplete.cmd`);
     - activator scripts;
     - drivers in `install.wim` that Microsoft didn't put there.
   - read `sources\ei.cfg`, where `Channel=eval` is a blocker;
   - read the `install.wim` XML header for EDITIONID (`ServerStandardEval` = eval), build and language;
   - read `sources\lang.ini`.
2. **Server baseline** (read-only, kept with the server's change record): OS, edition, build, InstallLanguage, MUI, activation, hotfix count, C: free space (≥ 20 GB), roles and features, key services with start mode, SQL patch level and service account, IIS sites and app pools, custom firewall rules, network config, installed software, and an application health check.
3. **App compatibility:** check every installed product against the target OS (see the matrix below).
4. **Snapshot or backup** of the VM before setup starts. On Proxmox, an LVM-thin snapshot is enough for a lab; production needs a backup.
5. **Change window:** the upgrade takes 30–90 min with several reboots, and the app is down throughout.

## Product compatibility notes

| Product | On 2012 R2 | On 2025 | Notes |
|---|---|---|---|
| SQL Server 2005 SP4 | **Not supported**, but usually works | **Not supported**, untested | Upgrade setup lists it as a compatibility issue. Plan to move the databases to a supported SQL version (2012 SP4+ can restore 2005 backups) before or after the OS upgrade. Test both hops. |
| IIS 7.5 → 8.5 → 10 | Upgraded in place | Upgraded in place | Sites, app pools and `web.config` carry over. ASP.NET 2.0/3.5 needs the .NET 3.5 feature, which setup normally keeps. |
| .NET 3.5 | Feature kept | Feature on demand (needs `sources\sxs` from the 2025 ISO if it's lost) | |

- **NIC Teaming** must be disabled before an in-place upgrade (Microsoft restriction).

## Gotchas found so far

- **2008 R2 tooling:** PowerShell 2.0, WinRM 2.0, default ExecutionPolicy `Restricted`.
  - Set `RemoteSigned`, or the IIS `WebAdministration` module won't load.
  - Configure the WinRM listener and firewall rule explicitly (`winrm create winrm/config/Listener?Address=*+Transport=HTTP`) rather than relying on `winrm quickconfig`.
  - pywinrm's `run_ps` is limited by the 8191-character command line. Upload scripts as files.
- **Unattended scripts on 2008 R2:**
  - `net user <name> <password> /add` stops to ask Y/N when the password is longer than 14 characters, which hangs unattended runs. Use ADSI or `/y`.
  - In PowerShell 2.0, `[ADSI]::Exists()` throws instead of returning `$false`.
- **IIS 7.5:** `Get-Website -Name X` ignores the name and returns every site. Use `Test-Path IIS:\Sites\X`.
- **Installing 2008 R2 RTM (pre-SP1) on Proxmox/QEMU:** setup freezes at "Expanding Windows files (0%)" (no disk I/O, ~2% CPU) when the disk or the DVD is on **SATA/AHCI**. The 2009 `msahci` driver doesn't get along with QEMU's AHCI.
  - Install with the disk and the DVD on **IDE**, and use the `other` OS type to avoid Hyper-V enlightenments, with `localtime=1`.
  - SP1 media installs fine on SATA with the `win7` OS type.
- **SP1 install reboots can use up a RunOnce entry.** The SP1 installer needs one reboot plus a configuration pass, and a RunOnce "phase 2" didn't fire. Run post-SP1 steps as a one-shot SYSTEM scheduled task (`schtasks /ru SYSTEM`), or check for them after logon.
- **After a failed or interrupted install, replace the disk.** If it holds a half-written bootable partition, the DVD's "Press any key to boot from CD" times out and the VM falls through to "BOOTMGR is missing".

## Server log

### SQL2005 (VM 118, 192.168.3.103): Windows Server 2008 R2 SP1 → 2012 R2 ✅ (2026-10-20)

**Source build:** a clean install of English Windows Server 2008 R2 SP1 Standard, then SQL Server 2005 SP4 Standard x64 and IIS 7.5 with the "Celtics Hub" app (see [github.com/theoneakta/celtics-app](https://github.com/theoneakta/celtics-app), folder `iis-sql2005/`).

**Media ACCEPTED, 2026-10-20:** `en_windows_server_2008_r2_standard_enterprise_datacenter_web_vl_build_x64_dvd_x15-59754.iso`.
- SHA-1 `ad855ea913aaec3f1d0e1833c1aef7a0de326b0a`, SHA-256 `181ba774…c1193cd`.
- Label `GRMSXVOL_EN_DVD`, `install.wim` untouched since 2009-07-14.
- No tool logs, no root answer file, no `$OEM$`, no `ei.cfg`.
- Build 6.1.7600.16385, which is **RTM, without SP1**. Volume-license build, en-US. Installed as Standard (index 1).
- *To do:* compare the SHA-1 with the VLSC/MSDN listing; no public Microsoft hash was available.

**SP1 is required** before an upgrade to 2012 R2. It came from the Microsoft Update Catalog, "Windows Server 2008 R2 Service Pack 1 for x64-based Systems (KB976932)":
- `windows6.1-kb976932-x64.exe`, SHA-1 `74865ef2…7a749dab`;
- its companion `windows6.1-kb2533552-x64.msu`, SHA-1 `0ba5ac38…cd04d`;
- both SHA-1s match the hashes in Microsoft's file names.

They were installed unattended at first logon, before SQL Server: `wusa /quiet /norestart` for the .msu, then `kb976932 /unattend /nodialog /norestart`, then a reboot.

**Baseline, 2026-10-20:** the "before" state for the 2012 R2 upgrade.

| Item | Value |
|---|---|
| OS | Windows Server 2008 R2 Standard SP1, 6.1.7601. PowerShell 2.0. |
| Install language / MUI | en-US (0409) / en-US |
| Activation | ServerStandard with the KMS client key (GVLK), not activated (grace period, 30 days) |
| Hotfixes | 3, including KB976932 (SP1) and KB2533552 |
| Hardware (Proxmox) | 2 vCPU (kvm64), 8 GB RAM, OS type win7, SeaBIOS. 60 GB disk on **IDE** (`ide0`, 41 GB free), e1000 NIC. |
| Roles/features | IIS 7.5 (static content, default doc, directory browsing, HTTP errors, ASP.NET, .NET extensibility, ISAPI, logging, request monitor, request filtering, static compression, management console), .NET Framework 3.5.1 |
| SQL | SQL Server 2005 SP4 Standard x64 (9.00.5000, PatchLevel 9.4.5000), default instance, mixed auth, collation `SQL_Latin1_General_CP1_CI_AS`. All services run as `NT AUTHORITY\NetworkService`. Databases: `roster_db` plus the system databases. |
| App | "Celtics Hub". IIS site `Celtics` (port 80, app pool `Celtics` .NET 2.0 integrated; Default Web Site stopped). Read-only DB access through `IIS APPPOOL\Celtics`. External feeder container (.8) writes hourly as SQL login `celtics_feeder`. Health check: `http://192.168.3.103/api/health` returns 200. |
| Services | MSSQLSERVER, SQLSERVERAGENT, SQLBrowser, SQLWriter, W3SVC, WinRM, MSDTC: Auto/Running. TermService: Manual/Running. |
| Firewall | Windows rules: Lab HTTP 80, Lab RDP 3389, Lab SQL Server 1433, Lab SQL Browser 1434, Lab ping (all LAN), WinRM5985 (192.168.3.8 only). The Proxmox per-VM firewall mirrors them: in-policy DROP, out = LAN only. |
| Network | DHCP 192.168.3.103, gateway and DNS 192.168.3.1 |
| Installed software | SQL Server 2005 x64 + Tools + Backward compatibility + SP4, SQL Native Client, VSS Writer, MSXML/Office 2003 Web Components, Visual Studio 2005 Premier Partner Edition (SSMS shell) |

**Pre-flight: ISO check, 2026-10-19:**
- `WinServer_2012_R2_English_x64.iso` (SHA-1 849734f3…, label `IR3_SSS_X64FREE_EN-US_DV9`) is **Evaluation** media: `ei.cfg Channel=eval`, editions `ServerStandardEval` and `ServerDatacenterEval`. It can't upgrade a licensed `ServerStandard`.
- **Needed:** a non-evaluation (retail, VL or MSDN) Windows Server 2012 R2 Standard ISO in English.

**Pre-flight: ISO check, 2026-10-20: PASSED.** `en_windows_server_2012_r2_x64_dvd_2707946.iso`.
- SHA-1 `b6f063436056510357cb19cb77db781ed9c11df3`, label `IRM_SSS_X64FRE_EN-US_DV5`.
- No `ei.cfg`, so not Evaluation. `install.wim` dated 2013-08-22, build 6.3.9600.16384 (RTM), en-US.
- No repack artifacts.
- Images: 1 Standard Core, **2 Standard (Server with a GUI)**, 3 Datacenter Core, 4 Datacenter GUI.

**Snapshot:** `win2008r2-sql2005` (with RAM), taken by the user before the upgrade.

#### Upgrade 2008 R2 SP1 → 2012 R2, 2026-10-20: **DONE**

**Working answer file** (`C:\lab\upgrade.xml`; run with `<dvd>:\setup.exe /unattend:C:\lab\upgrade.xml`). It contains no secrets: the key is Microsoft's published 2012 R2 Standard KMS client key.

```xml
<component name="Microsoft-Windows-Setup" processorArchitecture="amd64" ...>
  <UpgradeData><Upgrade>true</Upgrade><WillShowUI>OnError</WillShowUI></UpgradeData>
  <UserData>
    <AcceptEula>true</AcceptEula>
    <ProductKey><Key>D2N9P-3P6X9-2R39C-7RTCD-MDVJX</Key><WillShowUI>OnError</WillShowUI></ProductKey>
  </UserData>
  <ImageInstall><OSImage>
    <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>2</Value></MetaData></InstallFrom>
    <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>   <!-- the existing OS partition -->
    <WillShowUI>OnError</WillShowUI>
  </OSImage></ImageInstall>
  <DynamicUpdate><Enable>false</Enable><WillShowUI>Never</WillShowUI></DynamicUpdate>
  <ComplianceCheck><DisplayReport>Never</DisplayReport></ComplianceCheck>
</component>
```

**What stopped setup, in order** (each one stalled silently when setup ran as SYSTEM, since its dialogs stayed invisible):
1. **`<OSImage>` without `<InstallTo>`.** Setup reports *"Neither InstallToAvailablePartition nor InstallTo specified"* (0x80300007), and `InstallToAvailablePartition=false` doesn't count either. Fix: `<InstallTo>` pointing at the existing OS partition.
2. **No `<ImageInstall>` at all.** Setup stops at the **edition picker**, because the Standard KMS key matches both Core and GUI. Fix: `/IMAGE/INDEX` 2.
3. **The compatibility report page.** SQL Server 2005 is flagged *"Incompatible app … is not blocking upgrade"*, a soft block. The page still waits for **Confirm**, even with `ComplianceCheck/DisplayReport=Never`. Fix: run setup **on the console session**, not as SYSTEM, and press Confirm (or send Enter through the console).

**Monitoring:** follow `C:\$WINDOWS.~BT\Sources\Panther\setupact.log`. Lines with `PublishCriticalError` or `Entering Page` (with the log then going idle) mean setup is waiting. Two messages are harmless:
- `setuperr: Can't retrieve group information for user IIS APPPOOL\…`, because app pool identities are virtual accounts;
- `MIG … Failed to open HKEY_CURRENT_USER…`.

**Timeline:** about 25 min from launch to first logon on 2012 R2 (14:39 → 15:06 VM time), with 3 reboots. During the intermediate boots WinRM answers *"device not ready"* (HTTP 500).

**After the upgrade, compared with the baseline:**

| Item | Result |
|---|---|
| OS | Windows Server 2012 R2 Standard 6.3.9600, en-US. PowerShell 4.0 (PowerShell 2.0 engine kept as a feature). |
| SQL Server 2005 SP4 | Running, same NetworkService accounts, `roster_db` intact. `@@VERSION` now says "Windows NT 6.2 (Build 9200)"; SQL 2005 can't identify 2012 R2 (cosmetic). |
| IIS / app | IIS 7.5 → **8.5**. Site `Celtics` and its app pool kept. IIS added the standard `.NET v2.0` and `.NET v2.0 Classic` pools. `/api/health`, `/api/roster` and `/` return 200 from the LAN. |
| Roles/features | All kept. 2012 R2 defaults added: .NET 4.5 (+ASP.NET 4.5, WCF), FS-SMB1, File/Storage Services, PowerShell-V2. |
| Firewall / network | All six custom rules enabled. Same IP (DHCP) and gateway. NIC Intel 82574L kept its driver. |
| Hotfixes | 0. The 2008 R2 updates don't apply. Install the 2012 R2 Update next. |
| MSDTC | Stopped (start type Auto). It was Running on 2008 R2. Check after the next reboot. |
| Activation | **Notification mode** (status 5, 0 days of grace). The upgrade didn't keep the old grace period. In a lab without KMS: `slmgr /rearm`, then reboot. In production: a KMS host or MAK. |
| Disk | C: free space down from 41 GB to 33.5 GB (Windows.old plus the new OS). |

#### 2012 R2 Update (KB2919355), 2026-10-20: **DONE**

This is a prerequisite for later servicing and for the 2012 R2 → 2025 step.

- **Packages**, installed as a SYSTEM task with `wusa /quiet /norestart`, in Microsoft's order:
  1. **KB2919442** (servicing stack). It has been removed from the Update Catalog; the copy came from the [Download Center, id 42153](https://www.microsoft.com/en-ca/download/details.aspx?id=42153). Its Authenticode signature checked as *Valid, Microsoft Corporation*.
  2. `clearcompressionflag.exe`.
  3. **KB2919355**, about 14 min to install.
  4. KB2932046, KB2959977, KB2937592, KB2938439, KB2934018.
  
  All of these except KB2919442 came from the Update Catalog, with SHA-1s matching the hashes in Microsoft's file names. The `.msu` files return 3010 (reboot required).
- **Result:** build **6.3.9600.17041** (`winblue_gdr.140305-1710`). `Get-HotFix` lists KB2919355, KB2919442 and KB2959977; the other packages fold into KB2919355.
- **Reboot gotcha:** with pending updates, Proxmox's ACPI shutdown timed out after 10 min, and Windows ignored it while a console session was logged on. `shutdown /s` from inside Windows worked: "configuring updates" took 135 s, then the VM was off.
- **Proxmox:** OS type changed to `win8` (Windows 8 / 2012 R2) while the VM was off. 2 vCPU, disk still on IDE.

**Final state (2012 R2 + Update):**
- **Working:** SQL Server 2005 SP4, IIS 8.5 and the Celtics app. `/api/health`, `/api/roster`, `/api/mvp`, `/api/schedule` and `/` all return 200 from the LAN. All six firewall rules are in place, and the IP is unchanged. The feeder reconnected after the reboots: one sync failed during the downtime, then it resumed hourly.
- **Activation:** still in notification mode (status 5) after `slmgr /rearm` and a reboot. It's a KMS client key with no KMS host in the lab. That's a desktop watermark and reminders; Windows Server doesn't shut itself down. Production needs a KMS host or MAK.
- **MSDTC:** now *Automatic (Delayed Start)* and stopped at the time of the check. That's normal on 2012 R2, where it starts on demand. Celtics doesn't use distributed transactions.
- **Disk:** C: free 30.2 GB.

**Next hop:** 2012 R2 → **2025** (supported directly). Take a snapshot first. Re-check the SQL Server 2005 situation: it's unsupported on 2025, so move the databases to a supported SQL version first, or test carefully.
