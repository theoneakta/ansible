# [SERVER NAME] · Migration page

> **How to use this template.** Make one page per server, in the bundle's Loop workspace. Replace everything in *[brackets]* and delete the examples in *italics*. The rules behind each section are in the [migration governance guide](README.md).
>
> **Status values:** Not started · In progress · Blocked · Done · N/A

---

## At a glance

| | |
|---|---|
| **Server** | *[name]* |
| **Bundle** | *[e.g. B03-Finance]* |
| **What it does** | *[one or two sentences: the application or service, and who uses it]* |
| **OS / SQL** | *[e.g. Windows Server 2008 R2 · SQL Server 2008 R2 Standard]* |
| **Out of support since** | *[date]* |
| **Disposition** (decided at Gate 1) | *[Migrate · Consolidate · Retire]* |
| **Current phase** | *[Discovery · Install & test · Migration · Decommissioning · Done]* |
| **Target** | *[new server name, OS, SQL version · or "retire"]* |
| **Planned cut-over** | *[date]* |
| **Last updated** | *[date, name]* |

### Phase status

| Phase | Status | Gate signed (by · date) | Owner | Link |
|---|---|---|---|---|
| 1 · Discovery | Not started | | *[sysadmin / DBA]* | *[ADO story]* |
| 2 · Install & test | Not started | | *[sysadmin / DBA]* | *[ADO story]* |
| 3 · Migration | Not started | | *[tech lead]* | *[ADO story]* |
| 4 · Decommissioning | Not started | | *[sysadmin]* | *[ADO story]* |

---

## People

| Role | Name | Responsible for |
|---|---|---|
| **App owner (business)** | | Dependencies, UAT, acceptance (Gate 3), decisions about data |
| **SME** | | How the application works, its interfaces and its schedules |
| **Sysadmin** | | Server discovery, build, cut-over, decommissioning |
| **DBA** | | SQL discovery, build, data migration and validation |
| **Tech lead** | | Plan, decision log, gates 1, 2 and 4 |
| **PM** | | Planning, the blockers meeting, stakeholder updates |
| **Security / Cyber** | | Exceptions, cyber review |
| **Other stakeholders** | | *[teams or partners to keep informed]* |

---

## Links

| What | Link |
|---|---|
| ADO epic / feature | *[link]* |
| SharePoint folder | *[Migration/&lt;BUNDLE&gt;/&lt;SERVER&gt;/]* |
| Discovery summary (flags) | *[&lt;SERVER&gt;_SUMMARY_&lt;yyyyMMdd&gt;.csv]* |
| ServiceNow: server request | *[link]* |
| ServiceNow: change (CAB) | *[link]* |
| ServiceNow: decommission request | *[link]* |
| Architecture document | *[link]* |

---

## 1 · Discovery

**ADO story:** *[link]* · **Scripts version:** *[version or commit]* · **Capture week:** *[from – to]*

### Key findings

*[Three to five lines a non-technical reader can follow: what the server does, who connects to it, what's unusual.]*

### Dependencies (confirmed by the app owner)

| Direction | System / partner / device | Protocol / port | Purpose | Confirmed by |
|---|---|---|---|---|
| *Inbound* | *Partner X* | *FTP 21* | *Daily invoice drop in* `\\APP01\Inbound` | |
| *Outbound* | *SQL02* | *1433* | *Linked server for reporting* | |

### Monthly, quarterly and yearly jobs

The one-week capture doesn't see these, so each one needs an owner who confirms what it touches.

| Task / job | Schedule | What it touches | Owner confirmed |
|---|---|---|---|
| | | | |

### Gate 1 checklist

- [ ] Scripts ran from the approved version; output is in the SharePoint folder
- [ ] Summary reviewed by the sysadmin and the DBA
- [ ] Every RED flag has an owner and a decision (see *Flags and blockers*)
- [ ] App owner confirmed the dependencies and the unused data
- [ ] Disposition recorded: Migrate · Consolidate · Retire
- [ ] **Signed:** *[tech lead, date]*

---

## Flags and blockers

RED blocks progress until it's decided. AMBER needs a plan. Every decision also goes into the decision log.

| # | Finding | Flag | Plan / decision | Owner | Due | Status |
|---|---|---|---|---|---|---|
| 1 | *FTP flows (port 21 / SFTP 22) to partners* | *AMBER* | *Move to Kiteworks (MFT)* | | | Not started |
| 2 | *Clear-text passwords in scripts and config files* | *RED* | *Move to the vault; rotate the passwords* | | | Not started |
| 3 | *SMBv1 used by scanners* | *AMBER* | *Firmware update before cut-over* | | | Not started |

### Exceptions

Only for items that can't be fixed during the migration. Each one needs an end date.

| # | Item | Reason | Compensating control | Owner | End date | Approved by (Cyber) |
|---|---|---|---|---|---|---|
| | | | | | | |

---

## Migration strategy

| | |
|---|---|
| **Method** | *[In-place (1st choice) · side-by-side (2nd) · consolidation]* |
| **Path certainty** | *[Proven (lab or earlier server) · Uncertain → clone first]* |
| **Path** | *[e.g. SQL 2005 → 2016 (hop) → 2022 · Windows 2008 R2 → new 2022 server]* |
| **File transfers** | *[FTP flows → Kiteworks (MFT): list the flows]* |
| **Credentials** | *[Passwords found in files → vault; service accounts → gMSA where possible]* |
| **Legacy protocols** | *[SMBv1 / TLS 1.0 / NTLMv1: how each one is fixed on the target]* |
| **Data not migrated** | *[Archive, hand over or delete: the data owner's decision]* |
| **Rollback** | *[The source server stays untouched until Gate 3]* |

### Summary of steps

1. *[e.g. Build the target server (ServiceNow request)]*
2. *[e.g. Onboard the FTP flows on Kiteworks and test them with each partner]*
3. *[e.g. Rehearse the migration on a copy and time it]*
4. *[e.g. Cut over, validate, and get the app owner's sign-off]*

---

## 2 · Install & test

**ServiceNow server request:** *[link]* · **ADO task:** *[link]*

| Step | Status | Owner | Notes |
|---|---|---|---|
| *In-place:* clone run, **only if the path is uncertain** | Not started · N/A | Sysadmin | *[proven or uncertain, and why]* |
| *In-place:* OS upgrade and hardening | Not started | Sysadmin | *[OS hops, snapshots]* |
| *In-place:* **OS hand-off to the DBA** | Not started | Sysadmin → DBA | *[date]* · from here the DBA is responsible |
| *Side-by-side:* server built to the standard (OS, patches, OU, agents) | Not started | Sysadmin | |
| SQL installed and configured to the standard | Not started | | |
| Firewall rules and certificates | Not started | | |
| Kiteworks (MFT) flows set up | Not started | | |
| Credentials stored in the vault | Not started | | |
| Smoke test (the app starts and connects) | Not started | | |
| UAT on test data | Not started | | |

### Gate 2 checklist

- [ ] Build complete; deviations logged
- [ ] Backup and restore tested on the target
- [ ] Monitoring green
- [ ] **Signed:** *[tech lead, date]*

---

## 3 · Migration

### Approvals

| Approval | Status | Owner | Approver | Date | Evidence (link) |
|---|---|---|---|---|---|
| Architecture | Not started | | | | |
| Cyber | Not started | | | | |
| CAB (change) | Not started | | | | *[ServiceNow change]* |
| UAT sign-off | Not started | App owner | | | *[approval record]* |
| Go / no-go for cut-over | Not started | Tech lead | | | |

> **UAT sign-off:** use a record that can be audited and linked here. Two options:
> - **an approval on the ServiceNow change**, assigned to the app owner;
> - **a Teams Approvals request** sent to the app owner.
>
> An email or a chat message isn't enough evidence.

### Rehearsal

| Date | Duration measured | Issues found | Done by |
|---|---|---|---|
| | | | |

### Delta and cut-over

| | |
|---|---|
| **Delta steps** | *[final data sync, last files, last job runs: what moves at cut-over and in what order]* |
| **Freeze starts** | *[date and time; source read-only or services stopped]* |
| **Cut-over window** | *[date, start – end]* |
| **Point of no return** | *[time, and who decides]* |
| **Rollback plan** | *[link]* |

### Validation

- [ ] Data validated (row counts, CHECKDB, key reports)
- [ ] Every dependency tested, including the Kiteworks flows with partners
- [ ] Legacy-protocol flags closed, or covered by an exception
- [ ] First backup on the target, and a restore tested
- [ ] **Gate 3, signed by the app owner:** *[name, date, link to the approval]*

---

## 4 · Decommissioning

**ServiceNow decommission request:** *[link]*

| Step | Status | Owner | Date |
|---|---|---|---|
| Quiet period, or scream test for a retire (includes a month-end) | Not started | | |
| Data decision carried out (archive, hand over, delete) | Not started | | |
| SQL databases offline; final backup with a restore test | Not started | | |
| Server powered off (not deleted) | Not started | | |
| Removed from AD, DNS, DHCP, firewall | Not started | | |
| Removed from monitoring, backup, AV/EDR, patching | Not started | | |
| CMDB updated; licences reclaimed | Not started | | |
| Service accounts disabled; certificates revoked | Not started | | |
| VM deleted or hardware disposed of (disks wiped) | Not started | | |

- [ ] **Gate 4 signed:** *[tech lead, date]*

---

## Decision log

| ID | Date | Decision | Why | Decided by |
|---|---|---|---|---|
| | | | | |

## Change history

| Date | Who | What changed on this page |
|---|---|---|
| | | |
