# SQL Server 2005 on Windows Server 2025 — a stability showcase

This is the story of one lab VM (`SQL2005`, VM 118 on pve6, 192.168.3.103) that keeps a **real, continuously-serving web application** running on **SQL Server 2005** while the operating system underneath it is upgraded, in place, across **three generations** of Windows Server — and while the application itself grows from a single-team tracker into a 30-team one.

The point: a 2005-era database engine, treated well, is remarkably stable. Nothing here was reinstalled, re-platformed or restored from backup. The same `roster_db`, the same `MSSQLSERVER` instance, the same data files carried straight through every change below.

## The stack

| Layer | What | Notes |
|---|---|---|
| Hypervisor | Proxmox VE on pve6 | BIOS/MBR VM, IDE disk, CPU `x86-64-v2-AES` |
| OS | **Windows Server 2025** (24H2, 26100) | in-place upgraded from 2008 R2 SP1 → 2012 R2 → 2025 |
| Database | **SQL Server 2005 SP4** (9.00.5000) | default instance, mixed auth, never reinstalled |
| Web | **IIS 10** + ASP.NET 3.5 (C# handlers) | was IIS 7.5 on 2008 R2 |
| App | "NBA Hub" | roster / stats / schedule / MVP, all 30 teams, two seasons |
| Data feed | a container on another host (192.168.3.8) | pushes live data into SQL 2005 over TCP 1433 |

The application code lives in a separate public repo: **github.com/theoneakta/nbahub-app** (renamed from `celtics-app` on 2026-10-28) (`iis-sql2005/` = the web app on this box, `feeder/` = the data sync).

## 1. It survived three in-place OS upgrades with zero data loss

The OS was upgraded underneath the live app and database, in place, keeping every role, setting and byte of data:

| Hop | Result for SQL 2005 + the app |
|---|---|
| **2008 R2 SP1 → 2012 R2** | SQL 2005 services, logins and `roster_db` carried over untouched. IIS 7.5 → 8.5, site + app pool kept. App returned HTTP 200 after the upgrade. |
| **2012 R2 → 2025** | Same again. IIS 8.5 → 10. SQL 2005 still 9.00.5000, same NetworkService accounts, same data. App served immediately. |

SQL Server 2005 is **not supported** on 2012 R2 or 2025 — Microsoft's upgrade check flags it as an "incompatible application". It flags it as a **soft** block, not a hard one: the engine installs and runs anyway. Across both upgrades the database needed no repair, no reattach, no recovery intervention. Full upgrade mechanics and gotchas are in [README.md](README.md).

## 2. It passed fault-injection testing (on Windows Server 2025)

Deliberate failures were injected and recovery measured. SQL Server 2005 recovered cleanly from every one; `roster_db` ended with its exact row count and a clean `DBCC CHECKDB` each time.

| Fault injected | Behaviour |
|---|---|
| **Service stop/start** | Back up and accepting connections in a couple of seconds. The web app stayed at HTTP 200 (it reconnects on the next call). |
| **Hard process kill** (`sqlservr.exe` terminated — a simulated crash) | Crash recovery completed in **~1 second** — the write-ahead log replayed, all databases came online, *"SQL Server is now ready for client connections"*. Data intact, `DBCC CHECKDB` clean. |
| **Disk full** (volume filled to ~25 MB) | Reads kept working. Writes failed with the *correct* errors — `BACKUP` → OS error 112, an insert loop → **SQL 9002 "transaction log is full"**. No crash. After freeing space: full recovery, data intact. |
| **Memory pressure** (host RAM driven down to ~900 MB of 8 GB) | The app stayed at HTTP 200 (latency briefly ~95 ms), SQL kept answering, no crash. Full recovery once the pressure lifted. |

### The one weakness found — and fixed

The only fragility was **outside** the engine: SQL 2005's installer never set any **service recovery actions**, so a crashed `sqlservr.exe` stayed down until a reboot or a manual start. Fixed with:

```
sc failure MSSQLSERVER reset= 86400 actions= restart/5000/restart/10000/restart/30000
sc failure SQLBrowser  reset= 86400 actions= restart/5000/restart/10000/restart/30000
```

**Re-tested:** killed `sqlservr.exe` again — the Service Control Manager auto-restarted it and it was accepting connections **13.5 seconds later**, with no human action. Details in [README.md](README.md#sql-server-2005-resilience-test-2026-10-20-on-windows-server-2025).

## 3. The application kept growing on the 2005 database

While all of the above was going on, the app itself was extended repeatedly — each feature a normal schema change and query against SQL Server 2005, which handled every one without complaint:

- **Ported** from PostgreSQL + Node.js to **SQL Server 2005 + IIS/ASP.NET** (C# `IHttpHandler`s compiled on the fly from `App_Code`, no Visual Studio). Upserts without `MERGE`/`ON CONFLICT` (2005 has neither) use `UPDATE` then `IF @@ROWCOUNT = 0 INSERT`.
- **Multi-season** — a `season` dimension across all tables, a `/api/seasons` endpoint, and a year toggle. Historical rosters rebuilt from real season totals.
- **All 30 NBA teams** — a `team` dimension, a `teams` reference table (name + logo), a `/api/teams` endpoint, a team-logo grid and per-team pages. The 2005 database now holds **~1,180 player rows** (661 for 2025-26, 517 for 2026-27) across all 30 teams, plus 60 team schedules — all served to the page from SQL Server 2005 in milliseconds.
- **Live data** — an off-box feeder pushes the current rosters, stats, injuries and schedules into SQL 2005 hourly over TCP 1433 (the DB server itself stays offline and firewalled to the LAN).

A detail worth noting: SQL Server 2005 only speaks **TLS 1.0** on its login handshake, so the modern Node driver on the feeder is pinned to `tdsVersion 7_2` and allowed to negotiate TLS 1.0 for that one connection. Once connected, the 2005 engine serves a 2026-era application without issue.

## Bottom line

One SQL Server 2005 instance, never reinstalled, has:

- ridden through **Windows Server 2008 R2 → 2012 R2 → 2025** in-place, losing nothing;
- shrugged off **crash, disk-full and memory-pressure** fault injection, recovering its data cleanly every time (sub-second crash recovery);
- had its one real weakness (no auto-restart) found and fixed, then **verified self-healing**;
- served a **growing** web application throughout — now covering all 30 teams across two seasons.

It is, for a database engine two decades old running on an OS it was never meant to see, impressively stable. The honest caveats remain: SQL 2005 is out of support and unsupported on this OS, so this box is kept **LAN-only, firewalled, no internet**, and the real end state should still be a migration to a supported SQL version. But as a demonstration that the engine and its recovery machinery are solid, it speaks for itself.
