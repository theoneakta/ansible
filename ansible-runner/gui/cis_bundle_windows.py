"""Standalone CIS bundles for Windows: HardeningKitty (scipag, open source PowerShell) with CIS
finding lists, filtered to the same safety settings as playbooks/cis_hardening.yml. No Ansible,
no network - run on the machine itself in an admin PowerShell.

    cis-<os>/
      README.txt
      run-cis.ps1              -Mode Audit|Apply|Restore  -Level <see LEVELS>
      HardeningKitty/          the module (pinned commit)
      lists/<level>-machine.csv, <level>-user.csv     filtered CIS lists per level
      reports/                 audit reports, logs and the backups Apply makes first

Lists are matched to CIS levels through the GUI's ansible-lockdown role for the same OS - by
control number where both use the same benchmark version, by setting name otherwise (Windows 11:
the role follows CIS v3.0.0, HardeningKitty's list the 24H2 benchmark, and numbers moved).
A setting whose level can't be matched counts as Level 2 (left out of Level 1).
"""
import csv
import io
import json
import pathlib
import re
import shutil
import tempfile
import time
import urllib.request
import zipfile

import yaml

ROLES_DIR = pathlib.Path("/usr/share/ansible/roles")
HK_REPO = "scipag/HardeningKitty"
MAX_AGE = 7 * 86400

# key -> (HardeningKitty list base name, role, {level: (role level tags, extra name filter)})
PROFILES = {
    "windows11home": ("finding_list_cis_microsoft_windows_11_enterprise_24h2", "Windows-11-CIS", {
        "1-personal": ({"level1-corporate-enterprise-environment"}, "personal")}),
    "windows11": ("finding_list_cis_microsoft_windows_11_enterprise_24h2", "Windows-11-CIS", {
        "1-personal": ({"level1-corporate-enterprise-environment"}, "personal"),
        "1": ({"level1-corporate-enterprise-environment"}, None),
        "2": ({"level1-corporate-enterprise-environment", "level2-high-security-sensitive-data-environment"}, None)}),
    "windows2019": ("finding_list_cis_microsoft_windows_server_2019_1809_3.0.0", "Windows-2019-CIS", {
        "1-member": ({"level1-memberserver"}, "member"), "2-member": ({"level1-memberserver", "level2-memberserver"}, "member"),
        "1-dc": ({"level1-domaincontroller"}, "dc"), "2-dc": ({"level1-domaincontroller", "level2-domaincontroller"}, "dc")}),
    "windows2022": ("finding_list_cis_microsoft_windows_server_2022_22h2_4.0.0", "Windows-2022-CIS", {
        "1-member": ({"level1-memberserver"}, "member"), "2-member": ({"level1-memberserver", "level2-memberserver"}, "member"),
        "1-dc": ({"level1-domaincontroller"}, "dc"), "2-dc": ({"level1-domaincontroller", "level2-domaincontroller"}, "dc")}),
    "windows2025": ("finding_list_cis_microsoft_windows_server_2025_24h2_1.0.0", "Windows-2025-CIS", {
        "1-member": ({"level1-memberserver"}, "member"), "2-member": ({"level1-memberserver", "level2-memberserver"}, "member"),
        "1-dc": ({"level1-domaincontroller"}, "dc"), "2-dc": ({"level1-domaincontroller", "level2-domaincontroller"}, "dc")}),
}

# Left out of every list - the same controls playbooks/cis_hardening.yml skips (win_skip_for_test,
# <prefix>_rule_18_4_1): they cut off remote management (WinRM/RDP/network logon of the admin
# account, lockouts on failed automation logins) or break reboots. Matched by setting name.
SAFETY = re.compile(
    r"^(Account lockout duration|Account lockout threshold|Allow Administrator account lockout|Reset account lockout counter)"
    r"|^(Deny )?access (to )?this computer from the network|^Deny log on through Remote Desktop Services"
    r"|^(Accounts: )?Rename administrator account"
    r"|^(OpenSSH SSH Server|Remote Desktop Configuration|Remote Desktop Services|Windows Remote Management)\b"
    r"|Allow users to connect remotely by using Remote Desktop Services"
    r"|^WinRM (Client|Service):|Allow Remote Shell Access"
    r"|Apply UAC restrictions to local accounts on network logon|Apply local firewall rules \(Public", re.I)
# Also left out of Windows 11 "1-personal" - what broke the XPS (192.168.3.17), confirmed live:
# Microsoft-account sign-in, OneDrive/Outlook, account visibility; plus the other controls the
# playbook turns off for Windows 11 (LAN Manager level, OneDrive, consumer Microsoft accounts).
PERSONAL = re.compile(r"Block Microsoft accounts|Block all consumer Microsoft account|Prevent the usage of OneDrive"
                      r"|account details on sign-in|enumerate connected users|Enumerate local users"
                      r"|LAN Manager authentication level"
                      r"|Enable App Installer$|Only display the private store"
                      r"|Do not allow storage of passwords and credentials", re.I)


def _get(url: str, dest: pathlib.Path) -> pathlib.Path:
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url, timeout=300) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        tmp.rename(dest)
    return dest


def _role_controls(role: str) -> dict:
    """{control id: {"name": ..., "levels": {...}}} from the role's tasks."""
    out = {}

    def walk(tasks):
        for t in tasks or []:
            if not isinstance(t, dict):
                continue
            m = re.match(r"^\s*(\d+(?:\.\d+)+)\s*\|\s*(?:PATCH|AUDIT|MANUAL)\s*\|\s*(.+)", str(t.get("name", "")))
            if m:
                c = out.setdefault(m.group(1), {"name": m.group(2).split("|")[0].strip(), "levels": set()})
                c["levels"] |= {x for x in (t.get("tags") or []) if isinstance(x, str) and x.startswith("level")}
            for k in ("block", "rescue", "always"):
                walk(t.get(k))
    for f in sorted((ROLES_DIR / role).rglob("tasks/**/*.yml")):
        try:
            walk(yaml.safe_load(f.read_text(errors="ignore")))
        except Exception:
            pass
    return out


def _words(s: str) -> set:
    stop = {"ensure", "set", "the", "and", "for", "this", "that", "with", "from", "enabled", "disabled", "include",
            "configured", "policy", "computer", "windows", "settings", "setting"}
    return {w for w in re.findall(r"[a-z0-9]{3,}", s.lower()) if w not in stop}


def _levels_for(rows: list, role: dict) -> list:
    """CIS level tags for each HardeningKitty row: same id + similar name, else best name match."""
    by_words = [(cid, _words(c["name"]), c["levels"]) for cid, c in role.items()]
    out = []
    for r in rows:
        w = _words(r["Name"])
        c = role.get(r["ID"])
        if c and len(w & _words(c["name"])) >= max(1, min(2, len(w))):
            out.append(c["levels"])
            continue
        best, score = set(), 0.0
        for _cid, rw, lv in by_words:
            if not rw or not w:
                continue
            s = len(w & rw) / len(w | rw)
            if s > score:
                best, score = lv, s
        out.append(best if score >= 0.6 else set())
    return out


def _read_list(z: zipfile.ZipFile, top: str, name: str):
    data = z.read(f"{top}/lists/{name}").decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(data)))
    return list(rows[0].keys()) if rows else [], rows


RUN_PS1 = r'''<#
  CIS __LABEL__ with HardeningKitty - on THIS machine, offline. Run in an ADMIN PowerShell:
    .\run-cis.ps1 -Mode Audit   [-Level __DEFAULT__]   report only, nothing changes
    .\run-cis.ps1 -Mode Apply   [-Level __DEFAULT__]   backup first, then hardens (asks to confirm; -Yes skips)
    .\run-cis.ps1 -Mode Restore -Backup .\reports\<run>\backup-machine.csv   undo an Apply (best effort)
  Levels: __LEVELS__
  Reports: .\reports\<date>-<mode>-<level>\  (CSV report, log, and for Apply the backups)
#>
param(
  [Parameter(Mandatory)][ValidateSet('Audit', 'Apply', 'Restore')][string]$Mode,
  [ValidateSet(__LEVELSET__)][string]$Level = '__DEFAULT__',
  [string]$Backup,
  [switch]$Yes
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an administrator PowerShell.'
}
Get-ChildItem -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
Import-Module .\HardeningKitty\HardeningKitty.psd1 -Force
$os = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "This bundle: __LABEL__ (CIS via HardeningKitty).  This machine: $os"
$out = Join-Path 'reports' ("{0}-{1}-{2}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $Mode.ToLower(), $Level)
New-Item -ItemType Directory -Force $out | Out-Null
$lists = @{ machine = ".\lists\$Level-machine.csv"; user = ".\lists\$Level-user.csv" }

switch ($Mode) {
  'Audit' {
    foreach ($k in 'machine', 'user') {
      Invoke-HardeningKitty -Mode Audit -FileFindingList $lists[$k] -Log -LogFile "$out\audit-$k.log" -Report -ReportFile "$out\audit-$k.csv" -SkipRestorePoint
    }
  }
  'Apply' {
    if (-not $Yes) {
      Write-Host "`nAPPLY changes real security settings (password/lockout policy, services, network, UAC...) at level $Level." -ForegroundColor Yellow
      Write-Host 'A backup of the current values is saved first (reports folder) - restore with -Mode Restore -Backup <file>.'
      if ((Read-Host 'Type APPLY to continue') -ne 'APPLY') { Write-Host 'cancelled'; exit 1 }
    }
    foreach ($k in 'machine', 'user') {
      Invoke-HardeningKitty -Mode Config -Backup -BackupFile "$out\backup-$k.csv" -FileFindingList $lists[$k] -SkipRestorePoint
      Invoke-HardeningKitty -Mode HailMary -FileFindingList $lists[$k] -AllowCustomList -Log -LogFile "$out\apply-$k.log" -Report -ReportFile "$out\apply-$k.csv"
    }
    Write-Host "`nDone. Reboot, then run -Mode Audit to see the new score. Backups: $out\backup-*.csv"
  }
  'Restore' {
    if (-not $Backup -or -not (Test-Path $Backup)) { throw 'Give the backup file: -Backup .\reports\<run>\backup-machine.csv (and again for backup-user.csv)' }
    Invoke-HardeningKitty -Mode HailMary -FileFindingList $Backup -AllowCustomList -Log -LogFile "$out\restore.log" -Report -ReportFile "$out\restore.csv"
  }
}
Write-Host "Results in $out"
'''

README = """CIS {label} - standalone Windows bundle (HardeningKitty)
Generated by the ansible-runner GUI on {built}. HardeningKitty commit {sha} (github.com/{repo}).
CIS list: {hklist}

1. Copy the zip to the machine and extract it (e.g. C:\\cis\\).
2. Open PowerShell AS ADMINISTRATOR in that folder. If scripts are blocked:
       Set-ExecutionPolicy -Scope Process Bypass
3. .\\run-cis.ps1 -Mode Audit -Level {default}       report only, nothing changes
4. .\\run-cis.ps1 -Mode Apply -Level {default}       backs up current values first, then hardens; reboot after
   .\\run-cis.ps1 -Mode Restore -Backup .\\reports\\<run>\\backup-machine.csv   (and backup-user.csv) to undo

Levels in this bundle:
{levels}

"user" lists apply to the account that runs the script; run Audit/Apply as each user if needed.
Left out of every level (same as the ansible-runner GUI): remote-management controls - WinRM,
Remote Desktop, network logon/deny rights, UAC remote restrictions, account lockout - and
"apply local firewall rules (Public)". {personal_note}
This is a different engine than the GUI's Ansible roles: same CIS benchmark, but scores and the
exact set of checks differ. HardeningKitty's backup/restore is best effort (registry settings
restore well; some policies may not) - test on a non-critical machine first.
"""


def build(key: str, label: str, out_dir: pathlib.Path) -> pathlib.Path:
    hk_list, role, levels = PROFILES[key]
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"cis-{key}.zip"
    if out.exists() and out.stat().st_mtime > pathlib.Path(__file__).stat().st_mtime and time.time() - out.stat().st_mtime < MAX_AGE:
        return out
    sha = json.load(urllib.request.urlopen(f"https://api.github.com/repos/{HK_REPO}/commits/master", timeout=60))["sha"]
    hk_zip = _get(f"https://codeload.github.com/{HK_REPO}/zip/{sha}", out_dir / "cache" / f"HardeningKitty-{sha[:12]}.zip")
    controls = _role_controls(role)
    summary = []
    with zipfile.ZipFile(hk_zip) as z, tempfile.TemporaryDirectory() as tmp:
        top = z.namelist()[0].split("/")[0]
        root = pathlib.Path(tmp) / f"cis-{key}"
        (root / "lists").mkdir(parents=True)
        (root / "reports").mkdir()
        for n in z.namelist():   # the module itself (lists come filtered below)
            rel = n[len(top) + 1:]
            if rel and not rel.startswith(("lists/", ".")) and not n.endswith("/") and rel.split("/")[0] in ("HardeningKitty.psd1", "HardeningKitty.psm1", "LICENSE"):
                (root / "HardeningKitty").mkdir(exist_ok=True)
                (root / "HardeningKitty" / rel).write_bytes(z.read(n))
        for part in ("machine", "user"):
            fields, rows = _read_list(z, top, f"{hk_list}_{part}.csv")
            lv = _levels_for(rows, controls)
            for level, (tags, extra) in levels.items():
                keep = []
                full = any(t.startswith("level2") for t in tags)
                for r, l in zip(rows, lv):
                    name = r["Name"]
                    # level unknown (no matching role control) -> Level 2 only
                    if SAFETY.search(name) or not ((l & tags) or (full and not l)):
                        continue
                    if extra == "personal" and PERSONAL.search(name):
                        continue
                    if extra == "member" and "(DC" in name:
                        continue
                    if extra == "dc" and "(Member" in name:
                        continue
                    keep.append(r)
                with open(root / "lists" / f"{level}-{part}.csv", "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
                    w.writeheader()
                    w.writerows(keep)
                summary.append((level, part, len(keep), len(rows)))
        default = next(iter(levels))
        lv_txt = "\n".join(f"  {lvl:<11} machine {next(n for l, p, n, _ in summary if l == lvl and p == 'machine')} settings, "
                           f"user {next(n for l, p, n, _ in summary if l == lvl and p == 'user')}" for lvl in levels)
        (root / "run-cis.ps1").write_text(
            RUN_PS1.replace("__LABEL__", label).replace("__DEFAULT__", default)
            .replace("__LEVELSET__", ", ".join(f"'{l}'" for l in levels)).replace("__LEVELS__", ", ".join(levels)),
            encoding="utf-8-sig")
        note = ("Also left out of 1-personal: Microsoft-account sign-in blocks, OneDrive, account-visibility and "
                "LAN Manager level settings - what broke the XPS (sign-in, OneDrive/Outlook).") if key == "windows11" else ""
        (root / "README.txt").write_text(README.format(label=label, built=time.strftime("%Y-%m-%d"), sha=sha[:12], repo=HK_REPO,
                                                       hklist=hk_list, default=default, levels=lv_txt, personal_note=note),
                                         encoding="utf-8")
        tmp_out = out.with_suffix(".part")
        with zipfile.ZipFile(tmp_out, "w", zipfile.ZIP_DEFLATED) as zo:
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    zo.write(p, p.relative_to(root.parent))
        tmp_out.rename(out)
    return out


def summary(path: pathlib.Path) -> dict:
    """Row counts per list file inside a built bundle."""
    with zipfile.ZipFile(path) as z:
        return {n.split("/")[-1]: z.read(n).decode("utf-8").count("\n") - 1 for n in z.namelist() if n.endswith(".csv")}
